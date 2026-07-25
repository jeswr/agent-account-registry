"use strict";
// Live client-side refresh layer (progressive enhancement over the published snapshot).
//
// WHY: the published snapshot is a Pages artifact produced by the metrics cron, so it lags by
// the cron interval PLUS the Pages deploy time — measured at ~44 minutes on 2026-07-25
// (generated_at 14:06Z read at 14:50Z). For the four numbers the maintainer actually asks for
// every tick — merged today, open PR counts, the label census, and cron health — that lag is
// the difference between "useful" and "wrong". This layer re-derives exactly those four from
// the GitHub REST API in the browser and renders them ALONGSIDE the snapshot values.
//
// HARD CONSTRAINTS (all four are load-bearing; do not relax any of them):
//
//  1. NO CREDENTIAL, EVER. This page is served from a PUBLIC repo to anonymous visitors. There
//     is no token to send and none may ever be added — an `Authorization` header here would be
//     a published credential. Consequently every endpoint used below must be readable
//     anonymously, and nothing that is not already public can ever join this layer. Account
//     and fleet internals are deliberately absent: they are not publicly readable and must not
//     become so.
//  2. ANONYMOUS QUOTA IS 60 REQUESTS/HOUR PER IP, SHARED. The quota is not ours to spend
//     freely — a visitor behind a shared NAT shares it with everyone else there. So the poll
//     interval is DERIVED from the live quota headers (see liveBudget) rather than fixed, and a
//     reserve is always held back.
//  3. CONDITIONAL REQUESTS. Every response's ETag is cached and replayed as `If-None-Match`.
//     A 304 does not count against the rate limit, so an open tab watching an idle repo costs
//     approximately nothing. This is what makes (2) survivable.
//  4. NEVER PRESENT STALE DATA AS LIVE. Snapshot and live values carry separate, visible
//     timestamps; a live value that could be incomplete is rendered as a LOWER BOUND ("≥ 24");
//     and quota exhaustion degrades VISIBLY to snapshot-only with the resume time shown. A
//     silent fallback would make this panel a liar, which is worse than not having it.
//
// The pure decision logic is exported for `node dashboard/live.js --self-test`, following the
// repo's `--self-test` convention. The browser wiring is skipped under Node.

const LIVE_API = "https://api.github.com";
const LIVE_CACHE_KEY = "registry-live-etag-cache-v1";
const LIVE_MIN_INTERVAL_MS = 60_000;
const LIVE_MAX_INTERVAL_MS = 15 * 60_000;
// Held back so an exhausted layer still leaves a visitor's own quota usable elsewhere, and so a
// manual reload has something to spend.
const LIVE_QUOTA_RESERVE = 8;
// A scheduled workflow silent for this long is called out. Chosen to be well clear of the
// longest cron period in use (30m) so a normal gap never reads as a stall.
const LIVE_CRON_STALE_MS = 90 * 60_000;
const LIVE_PER_PAGE = 100;

// --- pure logic -----------------------------------------------------------------------------

// Derive the poll interval from the live quota so the layer paces ITSELF instead of trusting a
// hardcoded cadence to be affordable. Spend what is left (minus the reserve) evenly over the
// time remaining until the window resets.
function liveBudget({ remaining, resetAt, now, perCycle, reserve = LIVE_QUOTA_RESERVE,
                      minMs = LIVE_MIN_INTERVAL_MS, maxMs = LIVE_MAX_INTERVAL_MS }) {
  if (!Number.isFinite(perCycle) || perCycle <= 0) {
    return { paused: true, intervalMs: maxMs, reason: "no endpoints configured" };
  }
  // Unknown quota (first load, before any response) — probe once at the floor.
  if (!Number.isFinite(remaining)) {
    return { paused: false, intervalMs: minMs, reason: "quota unknown — probing" };
  }
  const spendable = remaining - reserve;
  if (spendable < perCycle) {
    return {
      paused: true,
      intervalMs: maxMs,
      reason: `quota exhausted (${remaining} left, reserve ${reserve})`,
      resumeAt: Number.isFinite(resetAt) ? resetAt : null,
    };
  }
  const msLeft = Number.isFinite(resetAt) && Number.isFinite(now) ? Math.max(0, resetAt - now) : null;
  if (msLeft === null) return { paused: false, intervalMs: minMs, reason: "reset time unknown" };
  const cycles = Math.floor(spendable / perCycle);
  const interval = cycles > 0 ? msLeft / cycles : maxMs;
  return {
    paused: false,
    intervalMs: Math.min(maxMs, Math.max(minMs, interval)),
    reason: `${cycles} cycle(s) affordable before reset`,
  };
}

function liveStartOfUtcDay(nowMs) {
  const d = new Date(nowMs);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
}

// Merged-today from the closed-PR list rather than the search API: the search index LAGS
// current state, and search carries a separate, much tighter quota. The list endpoint is
// authoritative and ETag-able.
//
// The page is finite, so the count can be a LOWER BOUND. It is under-counting precisely when
// the page came back FULL and its oldest entry is still inside today's window — meaning older
// merges exist that we cannot see. That case must be surfaced, never rounded off.
function liveMergedToday(closedPrs, nowMs, perPage = LIVE_PER_PAGE) {
  const dayStart = liveStartOfUtcDay(nowMs);
  let count = 0;
  let oldestUpdated = Infinity;
  for (const pr of closedPrs) {
    const updated = Date.parse(pr.updated_at || "");
    if (Number.isFinite(updated)) oldestUpdated = Math.min(oldestUpdated, updated);
    const merged = Date.parse(pr.merged_at || "");
    if (Number.isFinite(merged) && merged >= dayStart) count += 1;
  }
  const saturated = closedPrs.length >= perPage && oldestUpdated >= dayStart;
  return { count, lowerBound: saturated };
}

function liveOpenCounts(openPrs, perPage = LIVE_PER_PAGE) {
  let draft = 0;
  for (const pr of openPrs) if (pr.draft) draft += 1;
  return { open: openPrs.length, draft, lowerBound: openPrs.length >= perPage };
}

function liveLabelCensus(openPrs) {
  const counts = new Map();
  for (const pr of openPrs) {
    for (const label of pr.labels || []) {
      const name = label && typeof label.name === "string" ? label.name : null;
      if (!name) continue;
      counts.set(name, (counts.get(name) || 0) + 1);
    }
  }
  // Descending by count, then name, so the order is stable across refreshes.
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

// Latest scheduled run per workflow. `runs` arrives newest-first, but we resolve by comparing
// timestamps rather than trusting order — the same newest-per-name discipline the CI gate needs.
function liveCronHealth(runs, nowMs, staleMs = LIVE_CRON_STALE_MS) {
  const latest = new Map();
  for (const run of runs) {
    const name = run && typeof run.name === "string" ? run.name : null;
    if (!name) continue;
    const started = Date.parse(run.created_at || "");
    if (!Number.isFinite(started)) continue;
    const prev = latest.get(name);
    if (!prev || started > prev.startedMs) {
      latest.set(name, {
        name,
        startedMs: started,
        status: run.status || "unknown",
        conclusion: run.conclusion || null,
      });
    }
  }
  return [...latest.values()]
    .map((r) => ({
      ...r,
      ageMs: nowMs - r.startedMs,
      // A run still in flight is not stale however long ago it started.
      stale: r.status === "completed" && nowMs - r.startedMs > staleMs,
      failing: r.status === "completed" && r.conclusion !== null
        && !["success", "skipped", "neutral"].includes(r.conclusion),
    }))
    .sort((a, b) => {
      const rank = (x) => (x.failing ? 0 : x.stale ? 1 : 2);
      return rank(a) - rank(b) || a.name.localeCompare(b.name);
    });
}

function liveParseQuota(headers) {
  const get = (k) => {
    const v = headers && typeof headers.get === "function" ? headers.get(k) : null;
    const n = v === null || v === undefined ? NaN : Number(v);
    return Number.isFinite(n) ? n : NaN;
  };
  const remaining = get("x-ratelimit-remaining");
  const resetSec = get("x-ratelimit-reset");
  return {
    remaining: Number.isFinite(remaining) ? remaining : NaN,
    resetAt: Number.isFinite(resetSec) ? resetSec * 1000 : NaN,
  };
}

// --- browser wiring -------------------------------------------------------------------------

const liveIsBrowser = typeof window !== "undefined" && typeof document !== "undefined";

const liveState = {
  quota: { remaining: NaN, resetAt: NaN },
  perCycle: 0,
  timer: null,
  lastOkMs: null,
  repos: [],
  data: new Map(),   // repo -> { mergedToday, openCounts, census, cron, fetchedMs }
  paused: false,
  pausedReason: "",
  resumeAt: null,
};

function liveCacheLoad() {
  if (!liveIsBrowser) return {};
  try {
    return JSON.parse(window.localStorage.getItem(LIVE_CACHE_KEY) || "{}") || {};
  } catch { return {}; }
}

function liveCacheSave(cache) {
  if (!liveIsBrowser) return;
  try {
    window.localStorage.setItem(LIVE_CACHE_KEY, JSON.stringify(cache));
  } catch {
    // Quota-full or private-mode localStorage. The layer still works, it just re-spends API
    // quota on every reload instead of resuming from cache. Not worth surfacing.
  }
}

// Conditional GET. Returns { ok, body, notModified } and updates the quota state from headers.
// A 304 is a SUCCESS that cost no quota — that is the whole point of the ETag cache.
async function liveFetch(path) {
  const cache = liveCacheLoad();
  const entry = cache[path];
  const headers = { Accept: "application/vnd.github+json" };
  if (entry && entry.etag) headers["If-None-Match"] = entry.etag;

  let response;
  try {
    response = await fetch(`${LIVE_API}${path}`, { headers, cache: "no-store" });
  } catch {
    return { ok: false, body: null, notModified: false, error: "network" };
  }

  const quota = liveParseQuota(response.headers);
  if (Number.isFinite(quota.remaining)) liveState.quota.remaining = quota.remaining;
  if (Number.isFinite(quota.resetAt)) liveState.quota.resetAt = quota.resetAt;

  if (response.status === 304 && entry) {
    return { ok: true, body: entry.body, notModified: true };
  }
  if (response.status === 403 || response.status === 429) {
    // Distinguish quota exhaustion from any other refusal; only the former is a "come back
    // later", and it is the only one we advertise a resume time for.
    const exhausted = liveState.quota.remaining === 0;
    return { ok: false, body: null, notModified: false, error: exhausted ? "quota" : "forbidden" };
  }
  if (!response.ok) return { ok: false, body: null, notModified: false, error: `http ${response.status}` };

  let body;
  try { body = await response.json(); } catch { return { ok: false, body: null, notModified: false, error: "parse" }; }

  const etag = response.headers.get("etag");
  if (etag) {
    cache[path] = { etag, body };
    liveCacheSave(cache);
  }
  return { ok: true, body, notModified: false };
}

function liveEndpoints(repo) {
  return {
    open: `/repos/${repo}/pulls?state=open&per_page=${LIVE_PER_PAGE}`,
    closed: `/repos/${repo}/pulls?state=closed&sort=updated&direction=desc&per_page=${LIVE_PER_PAGE}`,
    cron: `/repos/${repo}/actions/runs?event=schedule&per_page=${LIVE_PER_PAGE}`,
  };
}

async function liveRefreshRepo(repo) {
  const ep = liveEndpoints(repo);
  const [open, closed, cron] = await Promise.all([liveFetch(ep.open), liveFetch(ep.closed), liveFetch(ep.cron)]);
  const now = Date.now();
  const prev = liveState.data.get(repo) || {};
  const next = { ...prev, fetchedMs: now, partial: false };

  if (open.ok && Array.isArray(open.body)) {
    next.openCounts = liveOpenCounts(open.body);
    next.census = liveLabelCensus(open.body);
  } else { next.partial = true; }

  if (closed.ok && Array.isArray(closed.body)) {
    next.mergedToday = liveMergedToday(closed.body, now);
  } else { next.partial = true; }

  if (cron.ok && cron.body && Array.isArray(cron.body.workflow_runs)) {
    next.cron = liveCronHealth(cron.body.workflow_runs, now);
  } else { next.partial = true; }

  liveState.data.set(repo, next);
  const errors = [open, closed, cron].filter((r) => !r.ok);
  return { quotaError: errors.some((r) => r.error === "quota"), anyOk: errors.length < 3 };
}

function liveFmtCount(value) {
  if (!value) return "—";
  return `${value.lowerBound ? "≥ " : ""}${value.count !== undefined ? value.count : value.open}`;
}

function liveRenderStatus() {
  const host = document.getElementById("live-status");
  if (!host) return;
  host.replaceChildren();
  const bits = [];
  if (liveState.paused) {
    bits.push(`Live refresh paused — ${liveState.pausedReason}`);
    if (liveState.resumeAt) {
      bits.push(`resumes ${new Date(liveState.resumeAt).toISOString().slice(11, 16)}Z`);
    }
    bits.push("showing snapshot only");
  } else if (liveState.lastOkMs) {
    bits.push(`Live ${new Date(liveState.lastOkMs).toISOString().slice(11, 16)}Z`);
    if (Number.isFinite(liveState.quota.remaining)) {
      bits.push(`quota ${liveState.quota.remaining} left`);
    }
  } else {
    bits.push("Live refresh starting…");
  }
  host.textContent = bits.join(" · ");
  host.dataset.state = liveState.paused ? "paused" : "live";
}

function liveRepoCard(repo, d) {
  const card = document.createElement("article");
  card.className = "live-card";
  const h = document.createElement("h3");
  h.className = "live-card-title";
  h.textContent = repo;
  card.append(h);

  const stats = document.createElement("div");
  stats.className = "live-stats";
  const stat = (label, value, note) => {
    const wrap = document.createElement("div");
    wrap.className = "live-stat";
    const l = document.createElement("p"); l.className = "live-stat-label"; l.textContent = label;
    const v = document.createElement("p"); v.className = "live-stat-value"; v.textContent = value;
    wrap.append(l, v);
    if (note) { const n = document.createElement("p"); n.className = "live-stat-note"; n.textContent = note; wrap.append(n); }
    return wrap;
  };
  stats.append(stat("Merged today (UTC)", liveFmtCount(d.mergedToday),
    d.mergedToday && d.mergedToday.lowerBound ? "lower bound — page saturated" : null));
  stats.append(stat("Open PRs", d.openCounts ? String(d.openCounts.open) : "—",
    d.openCounts ? `${d.openCounts.draft} draft` : null));
  card.append(stats);

  if (d.census && d.census.length) {
    const census = document.createElement("ul");
    census.className = "live-census";
    for (const [name, count] of d.census.slice(0, 12)) {
      const li = document.createElement("li");
      const n = document.createElement("span"); n.className = "live-census-name"; n.textContent = name;
      const c = document.createElement("span"); c.className = "live-census-count"; c.textContent = String(count);
      li.append(n, c);
      census.append(li);
    }
    const cap = document.createElement("p");
    cap.className = "live-census-caption";
    cap.textContent = d.census.length > 12
      ? `label census — top 12 of ${d.census.length}`
      : "label census (open PRs)";
    card.append(cap, census);
  }

  if (d.cron && d.cron.length) {
    const problems = d.cron.filter((c) => c.failing || c.stale);
    const cap = document.createElement("p");
    cap.className = "live-census-caption";
    cap.textContent = problems.length
      ? `cron health — ${problems.length} of ${d.cron.length} need attention`
      : `cron health — all ${d.cron.length} scheduled workflows healthy`;
    card.append(cap);
    const list = document.createElement("ul");
    list.className = "live-cron";
    for (const c of (problems.length ? problems : d.cron).slice(0, 8)) {
      const li = document.createElement("li");
      li.dataset.state = c.failing ? "failing" : c.stale ? "stale" : "ok";
      const n = document.createElement("span"); n.className = "live-cron-name"; n.textContent = c.name;
      const s = document.createElement("span"); s.className = "live-cron-meta";
      const mins = Math.round(c.ageMs / 60000);
      s.textContent = `${c.status === "completed" ? (c.conclusion || "done") : c.status} · ${mins}m ago`;
      li.append(n, s);
      list.append(li);
    }
    card.append(list);
  }

  if (d.partial) {
    const warn = document.createElement("p");
    warn.className = "live-partial";
    warn.textContent = "some live endpoints unavailable — values above may be from an earlier poll";
    card.append(warn);
  }
  return card;
}

function liveRender() {
  liveRenderStatus();
  const section = document.getElementById("live-section");
  const host = document.getElementById("live-targets");
  if (!section || !host) return;
  const rendered = liveState.repos.filter((r) => liveState.data.has(r));
  if (!rendered.length) { section.hidden = true; return; }
  section.hidden = false;
  host.replaceChildren();
  for (const repo of rendered) host.append(liveRepoCard(repo, liveState.data.get(repo)));
}

function liveSchedule() {
  const budget = liveBudget({
    remaining: liveState.quota.remaining,
    resetAt: liveState.quota.resetAt,
    now: Date.now(),
    perCycle: liveState.perCycle,
  });
  liveState.paused = budget.paused;
  liveState.pausedReason = budget.reason;
  liveState.resumeAt = budget.resumeAt || null;
  if (liveState.timer) clearTimeout(liveState.timer);
  // Even when paused we re-arm: the reset time passes and the quota comes back, and the layer
  // must resume on its own. A hold whose only exit is a page reload is the same defect as a
  // machine-owned park with no machine-side exit.
  liveState.timer = setTimeout(liveTick, budget.paused
    ? Math.max(LIVE_MIN_INTERVAL_MS, Math.min(LIVE_MAX_INTERVAL_MS,
        (liveState.resumeAt || 0) - Date.now() || LIVE_MAX_INTERVAL_MS))
    : budget.intervalMs);
  liveRenderStatus();
}

async function liveTick() {
  if (!liveState.repos.length) { liveSchedule(); return; }
  if (!liveState.paused) {
    let anyOk = false;
    for (const repo of liveState.repos) {
      const result = await liveRefreshRepo(repo);
      anyOk = anyOk || result.anyOk;
    }
    if (anyOk) liveState.lastOkMs = Date.now();
    liveRender();
  }
  liveSchedule();
}

// The repo list comes from the snapshot's own `targets` keys so the live layer can never drift
// out of sync with what the collector watches, and no repo name is hardcoded here.
function liveSetRepos(repos) {
  const valid = (repos || []).filter((r) => /^[A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w.-]*$/.test(r));
  const changed = valid.join(",") !== liveState.repos.join(",");
  liveState.repos = valid;
  liveState.perCycle = valid.length * 3; // open + closed + cron per repo
  if (changed && valid.length) liveTick();
}

if (liveIsBrowser) {
  window.registryLive = { setRepos: liveSetRepos, state: liveState };
}

// --- self-test ------------------------------------------------------------------------------

function liveSelfTest() {
  const failures = [];
  const check = (name, cond) => { if (!cond) failures.push(name); };
  const HOUR = 3600_000;
  const now = Date.parse("2026-07-25T14:50:00Z");
  const dayStart = Date.parse("2026-07-25T00:00:00Z");

  // liveBudget — the guard that stops this layer from burning a shared 60/hr quota.
  const plenty = liveBudget({ remaining: 60, resetAt: now + HOUR, now, perCycle: 6 });
  check("budget: healthy quota is not paused", plenty.paused === false);
  check("budget: healthy interval respects the floor", plenty.intervalMs >= LIVE_MIN_INTERVAL_MS);
  // BEHAVIOUR, not the constant: whatever interval it picks must be affordable — the number of
  // cycles that fit before reset must not need more requests than we are allowed to spend.
  const cyclesUsed = Math.floor(HOUR / plenty.intervalMs);
  check("budget: chosen cadence is affordable", cyclesUsed * 6 <= 60 - LIVE_QUOTA_RESERVE);

  const broke = liveBudget({ remaining: LIVE_QUOTA_RESERVE, resetAt: now + HOUR, now, perCycle: 6 });
  check("budget: at the reserve it pauses", broke.paused === true);
  check("budget: paused state advertises a resume time", broke.resumeAt === now + HOUR);
  const nearly = liveBudget({ remaining: LIVE_QUOTA_RESERVE + 3, resetAt: now + HOUR, now, perCycle: 6 });
  check("budget: fewer than one cycle spendable pauses", nearly.paused === true);
  check("budget: unknown quota probes rather than pausing",
    liveBudget({ remaining: NaN, resetAt: NaN, now, perCycle: 6 }).paused === false);
  check("budget: zero endpoints pauses", liveBudget({ remaining: 60, resetAt: now + HOUR, now, perCycle: 0 }).paused === true);

  // liveMergedToday — the lower-bound guard. This is the honesty-critical one: an under-count
  // presented as exact would be the dashboard lying about throughput.
  const merged = liveMergedToday([
    { merged_at: "2026-07-25T10:00:00Z", updated_at: "2026-07-25T10:00:00Z" },
    { merged_at: "2026-07-25T02:00:00Z", updated_at: "2026-07-25T02:00:00Z" },
    { merged_at: "2026-07-24T23:59:59Z", updated_at: "2026-07-24T23:59:59Z" }, // yesterday
    { merged_at: null, updated_at: "2026-07-25T09:00:00Z" },                    // closed unmerged
  ], now, 100);
  check("merged: counts only today's merges", merged.count === 2);
  check("merged: a short page is exact", merged.lowerBound === false);

  const saturated = Array.from({ length: 5 }, (_, i) => ({
    merged_at: new Date(dayStart + (i + 1) * 60_000).toISOString(),
    updated_at: new Date(dayStart + (i + 1) * 60_000).toISOString(),
  }));
  const sat = liveMergedToday(saturated, now, 5);
  check("merged: a full page still inside today is a LOWER BOUND", sat.lowerBound === true && sat.count === 5);
  const satOld = liveMergedToday([
    ...saturated.slice(0, 4),
    { merged_at: "2026-07-20T00:00:00Z", updated_at: "2026-07-20T00:00:00Z" },
  ], now, 5);
  check("merged: a full page reaching past today is exact", satOld.lowerBound === false);

  // liveOpenCounts / liveLabelCensus
  const prs = [
    { draft: true, labels: [{ name: "review:needs-user" }, { name: "trust-surface" }] },
    { draft: false, labels: [{ name: "review:needs-user" }] },
    { draft: false, labels: [] },
    { draft: false, labels: [{ name: null }, { name: "trust-surface" }] },
  ];
  const counts = liveOpenCounts(prs, 100);
  check("open: counts open and draft", counts.open === 4 && counts.draft === 1);
  const census = liveLabelCensus(prs);
  check("census: descending by count", census[0][0] === "review:needs-user" && census[0][1] === 2);
  check("census: ignores malformed label entries", census.every(([n]) => typeof n === "string" && n));
  check("census: total labels", census.length === 2);

  // liveCronHealth — newest-per-name, and an in-flight run is not stale.
  // The two `metrics` entries are deliberately OLDEST-FIRST. If they were newest-first, a
  // first-seen-wins implementation would agree with newest-wins on this fixture and the
  // assertion below would pass without testing the resolution discipline at all.
  const cron = liveCronHealth([
    { name: "metrics", created_at: "2026-07-25T09:00:00Z", status: "completed", conclusion: "failure" },
    { name: "metrics", created_at: "2026-07-25T14:45:00Z", status: "completed", conclusion: "success" },
    { name: "groom", created_at: "2026-07-25T10:00:00Z", status: "completed", conclusion: "success" },
    { name: "dispatch", created_at: "2026-07-25T11:00:00Z", status: "in_progress", conclusion: null },
    { name: "worker", created_at: "2026-07-25T14:40:00Z", status: "completed", conclusion: "failure" },
  ], now);
  const byName = Object.fromEntries(cron.map((c) => [c.name, c]));
  check("cron: resolves the NEWEST run per name, not the first seen",
    byName.metrics.conclusion === "success" && byName.metrics.stale === false);
  check("cron: an old completed run is stale", byName.groom.stale === true);
  check("cron: an in-flight run is never stale", byName.dispatch.stale === false);
  check("cron: a failing run is flagged", byName.worker.failing === true);
  check("cron: problems sort first", cron[0].failing === true);

  // liveParseQuota tolerates absent/garbage headers rather than inventing a number, because a
  // fabricated `remaining` would defeat the pacing guard above.
  const q = liveParseQuota({ get: (k) => ({ "x-ratelimit-remaining": "42", "x-ratelimit-reset": "1785000000" }[k] ?? null) });
  check("quota: parses headers", q.remaining === 42 && q.resetAt === 1785000000000);
  const qn = liveParseQuota({ get: () => null });
  check("quota: absent headers yield NaN, not 0", Number.isNaN(qn.remaining) && Number.isNaN(qn.resetAt));

  if (failures.length) {
    console.error(`live.js self-test FAILED (${failures.length}):`);
    for (const f of failures) console.error(`  - ${f}`);
    return 1;
  }
  console.log("live.js self-test passed");
  return 0;
}

if (!liveIsBrowser && typeof process !== "undefined") {
  if (process.argv.includes("--self-test")) process.exit(liveSelfTest());
  else { console.error("usage: node dashboard/live.js --self-test"); process.exit(2); }
}
