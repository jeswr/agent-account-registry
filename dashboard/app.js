"use strict";

const REFRESH_MS = 60_000;
const STALE_MS = 30 * 60_000;
const byId = (id) => document.getElementById(id);
const relativeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function parseTime(value) {
  const date = value ? new Date(value) : null;
  return date && Number.isFinite(date.getTime()) ? date : null;
}

function utc(value) {
  const date = parseTime(value);
  if (!date) return "unknown";
  return new Intl.DateTimeFormat(undefined, {
    timeZone: "UTC", dateStyle: "medium", timeStyle: "short", hour12: false,
  }).format(date) + " UTC";
}

function relative(value) {
  const date = parseTime(value);
  if (!date) return "unknown";
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const ranges = [[86400, "day"], [3600, "hour"], [60, "minute"]];
  for (const [size, unit] of ranges) {
    if (Math.abs(seconds) >= size) return relativeFormatter.format(Math.round(seconds / size), unit);
  }
  return relativeFormatter.format(seconds, "second");
}

function summaryCard(label, value, meta) {
  const card = node("article", "summary-card");
  card.append(node("p", "summary-label", label), node("p", "summary-value", value));
  if (meta) card.append(node("p", "summary-meta", meta));
  return card;
}

function renderSummary(data) {
  const summary = byId("summary");
  summary.replaceChildren();
  summary.append(summaryCard(
    "Active agents", String(data.fleet.active_agents),
    data.fleet.active_agents === 1 ? "1 live lease" : `${data.fleet.active_agents} live leases`,
  ));

  const capacity = node("article", "summary-card");
  capacity.append(node("p", "summary-label", "Provider capacity"));
  const lines = node("div", "provider-lines");
  const providers = Object.entries(data.fleet.capacity || {}).sort(([left], [right]) => (
    left.localeCompare(right)
  ));
  for (const [provider, values] of providers) {
    const line = node("div", "provider-line");
    line.append(node("span", "", provider), node("strong", "", `${values.eligible} / ${values.total}`));
    lines.append(line);
  }
  if (!providers.length) lines.append(node("p", "summary-meta", "No provider records"));
  capacity.append(lines);
  summary.append(capacity);
  summary.append(summaryCard(
    "Last dispatch sweep", data.fleet.last_sweep_at ? relative(data.fleet.last_sweep_at) : "unknown",
    data.fleet.last_sweep_at ? utc(data.fleet.last_sweep_at) : "No completed sweep data",
  ));
  summary.append(summaryCard("Data freshness", relative(data.generated_at), utc(data.generated_at)));
}

function renderWindow(windowData) {
  const wrapper = node("div", "window");
  const head = node("div", "window-head");
  const percent = windowData.used_percent;
  const known = typeof percent === "number" && Number.isFinite(percent);
  const limit = windowData.limit ? ` · limit ${windowData.limit}` : "";
  head.append(
    node("span", "window-name", windowData.name + limit),
    node("span", "window-value", known ? `${percent.toFixed(percent % 1 ? 1 : 0)}% used` : "unknown"),
  );
  const meter = node("div", "meter");
  meter.setAttribute("role", "progressbar");
  meter.setAttribute("aria-label", `${windowData.name} quota utilization`);
  if (known) {
    meter.setAttribute("aria-valuenow", String(percent));
    meter.setAttribute("aria-valuemin", "0");
    meter.setAttribute("aria-valuemax", "100");
    const fill = node("span", percent >= 85 ? "high" : "");
    fill.style.width = `${Math.min(100, Math.max(0, percent))}%`;
    meter.append(fill);
  }
  const resetText = windowData.reset_at
    ? `Resets ${relative(windowData.reset_at)} · ${utc(windowData.reset_at)}`
    : "Reset unknown";
  wrapper.append(head, meter, node("p", "reset", resetText));
  return wrapper;
}

function renderWeeklyReset(resetAt) {
  const reset = node("div", "weekly-reset");
  reset.append(node("span", "weekly-reset-label", "Weekly reset"));
  if (parseTime(resetAt)) {
    reset.append(
      node("strong", "weekly-reset-relative", relative(resetAt)),
      node("span", "weekly-reset-utc", utc(resetAt)),
    );
  } else {
    reset.append(
      node("strong", "weekly-reset-relative", "Unknown"),
      node("span", "weekly-reset-utc", "No 7 day reset in the latest snapshot"),
    );
  }
  return reset;
}

function accountCard(account) {
  const card = node("article", "account-card");
  const top = node("div", "card-top");
  top.append(node("h4", "account-label", account.label));
  const badges = node("div", "badges");
  badges.append(node("span", `badge ${account.availability}`, account.availability));
  top.append(badges);
  const agents = node("div", "agent-count");
  agents.append(node("span", "", "Active agents"), node("strong", "", String(account.active_agents)));
  const windows = node("div", "window-list");
  for (const windowData of account.windows) windows.append(renderWindow(windowData));
  card.append(top, renderWeeklyReset(account.weekly_reset_at), agents, windows);
  return card;
}

function renderAccounts(accounts) {
  const container = byId("accounts");
  container.replaceChildren();
  byId("account-count").textContent = `${accounts.length} account${accounts.length === 1 ? "" : "s"}`;
  if (!accounts.length) {
    container.append(node("p", "empty", "No account records are available."));
    return;
  }

  const groups = new Map();
  for (const account of accounts) {
    if (!groups.has(account.provider)) groups.set(account.provider, []);
    groups.get(account.provider).push(account);
  }
  for (const [provider, providerAccounts] of groups) {
    const section = node("section", "provider-section");
    const heading = node("div", "provider-heading");
    heading.append(
      node("h3", "provider-title", provider),
      node("span", "freshness", `${providerAccounts.length} account${providerAccounts.length === 1 ? "" : "s"}`),
    );
    const grid = node("div", "account-grid");
    for (const account of providerAccounts) grid.append(accountCard(account));
    section.append(heading, grid);
    container.append(section);
  }
}

// --- Provider quota (cumulative): per-provider AGGREGATE headroom across that provider's
// accounts, computed server-side by dashboard-gen._provider_quota from the signals that actually
// exist — live per-window utilization probes where the provider exposes them (anthropic), and
// only the availability counts + reactive backoff where it does not (probe-exempt openai).
// Accounts the fail-closed probe OMITTED surface as `accounts_unknown` ("unreported") and are
// never rendered free — dispatch treats that omission as unavailable (sol finding 2, PR #281);
// so do PARTIAL probe entries (status-only / one window without the other), which dispatch and
// usage-alert equally reject (sol finding 1, PR #281 fix round 3).
// The honest aggregate unit is "account-windows free" (Σ remaining window fraction over the
// accounts that reported), with a PARTIAL limit-weighted sum only where limit headers are known;
// each card states its signal source, and the section header carries the snapshot freshness.
// An absent `provider_quota` key (older data.json) hides the whole section. Decision 22: rows
// contain provider names + counts only — no account identifiers of any form. ---------------------
function quotaWindowRow(windowData) {
  const wrap = node("div", "window");
  const head = node("div", "window-head");
  const remaining = typeof windowData.remaining_account_windows === "number"
    && Number.isFinite(windowData.remaining_account_windows)
    ? windowData.remaining_account_windows : null;
  const reporting = Number.isInteger(windowData.accounts_reporting)
    ? windowData.accounts_reporting : 0;
  head.append(
    node("span", "window-name", windowData.name),
    node("span", "window-value", remaining === null || !reporting
      ? "unknown"
      : `${remaining} of ${reporting} account-window${reporting === 1 ? "" : "s"} free`),
  );
  const meter = node("div", "meter");
  meter.setAttribute("role", "progressbar");
  meter.setAttribute("aria-label", `${windowData.name} aggregate remaining quota`);
  if (remaining !== null && reporting > 0) {
    const fraction = Math.min(1, Math.max(0, remaining / reporting));
    meter.setAttribute("aria-valuenow", String(Math.round(fraction * 100)));
    meter.setAttribute("aria-valuemin", "0");
    meter.setAttribute("aria-valuemax", "100");
    const fill = node("span", fraction <= 0.15 ? "high" : "");
    fill.style.width = `${fraction * 100}%`;
    meter.append(fill);
  }
  const notes = [];
  if (typeof windowData.limit_remaining === "number"
      && Number.isFinite(windowData.limit_remaining)) {
    notes.push(`≈${windowData.limit_remaining.toLocaleString()} provider limit-units left`
      + ` (limits known for ${windowData.limits_known}/${reporting})`);
  }
  if (windowData.soonest_reset) {
    notes.push(`next reset ${relative(windowData.soonest_reset)}`
      + (windowData.oldest_reset && windowData.oldest_reset !== windowData.soonest_reset
        ? ` · last ${relative(windowData.oldest_reset)}` : ""));
  }
  wrap.append(head, meter, node("p", "reset", notes.length ? notes.join(" · ") : "Reset unknown"));
  return wrap;
}

function providerQuotaCard(row) {
  const card = node("article", "account-card quota-card");
  const top = node("div", "card-top");
  top.append(node("h4", "quota-provider", String(row.provider || "unknown")));
  const badges = node("div", "badges");
  if (row.single_account) badges.append(node("span", "badge", "single account"));
  if (Number.isInteger(row.accounts_capped) && row.accounts_capped > 0) {
    badges.append(node("span", "badge capped", `${row.accounts_capped} capped`));
  }
  if (Number.isInteger(row.accounts_unknown) && row.accounts_unknown > 0) {
    // Distinct neutral badge: an unreported (fail-closed-omitted) account is NOT free — the
    // muted default badge style separates "no signal" from green/amber/red real states.
    badges.append(node("span", "badge", `${row.accounts_unknown} unreported`));
  }
  top.append(badges);
  const total = Number.isInteger(row.accounts_total) ? row.accounts_total : 0;
  let countsText = `${total} account${total === 1 ? "" : "s"}`
    + ` · ${Number.isInteger(row.accounts_available) ? row.accounts_available : 0} free`
    + ` · ${Number.isInteger(row.accounts_capped) ? row.accounts_capped : 0} capped`;
  if (Number.isInteger(row.accounts_unavailable) && row.accounts_unavailable > 0) {
    countsText += ` · ${row.accounts_unavailable} unavailable`;
  }
  if (Number.isInteger(row.accounts_unknown) && row.accounts_unknown > 0) {
    countsText += ` · ${row.accounts_unknown} unreported — treated unavailable by dispatch`;
  }
  const windows = node("div", "window-list");
  const windowRows = Array.isArray(row.windows) ? row.windows : [];
  for (const windowData of windowRows) windows.append(quotaWindowRow(windowData));
  if (!windowRows.length) {
    windows.append(node("p", "quota-note",
      "Aggregate remaining quota is not observable for this provider — availability and capped counts above are the only real signal."));
  }
  card.append(top, node("p", "quota-counts", countsText), windows);
  if (row.soonest_reset) {
    card.append(node("p", "quota-note",
      `Soonest known reset ${relative(row.soonest_reset)} · all known windows reset by ${utc(row.oldest_reset)}`));
  }
  card.append(node("p", "quota-signal", `Signal: ${String(row.signal || "unknown")}`));
  return card;
}

function renderProviderQuota(rows, generatedAt) {
  const section = byId("provider-quota-section");
  if (!Array.isArray(rows) || !rows.length) {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  byId("provider-quota-time").textContent = generatedAt
    ? `Data as of ${relative(generatedAt)} · ${utc(generatedAt)}` : "Data freshness unknown";
  byId("provider-quota").replaceChildren(...rows.map(providerQuotaCard));
}

function renderRepositoryAgents(activity, activeAgents) {
  if (!activity || !Array.isArray(activity.models) || !Array.isArray(activity.repositories)) {
    throw new Error("invalid repository activity snapshot");
  }
  const modelPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/;
  const repositoryPattern = /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/;
  const models = activity.models;
  if (new Set(models).size !== models.length || models.some((model) => !modelPattern.test(model))) {
    throw new Error("invalid model columns in repository activity snapshot");
  }
  let total = 0;
  for (const row of activity.repositories) {
    if (!row || !repositoryPattern.test(row.repository) || !row.counts || Array.isArray(row.counts)) {
      throw new Error("invalid repository row in activity snapshot");
    }
    for (const [model, count] of Object.entries(row.counts)) {
      if (!models.includes(model) || !Number.isInteger(count) || count < 0) {
        throw new Error("invalid model count in repository activity snapshot");
      }
      total += count;
    }
  }
  if ((!activity.repositories.length && models.length) || total !== activeAgents) {
    throw new Error("repository activity does not match live lease count");
  }

  const empty = byId("repo-agents-empty");
  const table = byId("repo-agents-table");
  const head = byId("repo-agents-head");
  const body = byId("repo-agents-body");
  if (!activity.repositories.length) {
    empty.textContent = "No agents currently active.";
    empty.hidden = false;
    table.hidden = true;
    head.replaceChildren();
    body.replaceChildren();
    return;
  }

  const header = node("tr");
  header.append(node("th", "", "Repository"));
  for (const model of models) header.append(node("th", "numeric", model));
  const rows = [];
  for (const repository of activity.repositories) {
    const row = node("tr");
    row.append(node("td", "repository", repository.repository));
    for (const model of models) row.append(node("td", "numeric", String(repository.counts[model] || 0)));
    rows.push(row);
  }
  head.replaceChildren(header);
  body.replaceChildren(...rows);
  empty.hidden = true;
  table.hidden = false;
}

function renderOutcomes(outcomes) {
  const body = byId("outcomes");
  body.replaceChildren();
  if (!outcomes.length) {
    const row = node("tr");
    const cell = node("td", "", "No dispatch history is available.");
    cell.colSpan = 4;
    row.append(cell);
    body.append(row);
    return;
  }
  for (const outcome of outcomes) {
    const row = node("tr");
    const result = node("span", `badge ${outcome.conclusion}`, outcome.conclusion);
    const resultCell = node("td");
    resultCell.append(result);
    row.append(
      node("td", "", `${relative(outcome.at)} · ${utc(outcome.at)}`), resultCell,
      node("td", "", outcome.dispatched === null ? "—" : String(outcome.dispatched)),
      node("td", "", outcome.deferred === null ? "—" : String(outcome.deferred)),
    );
    body.append(row);
  }
}

function renderHealth(health) {
  const section = byId("health-section");
  if (!health) {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  byId("health-time").textContent = health.generated_at
    ? `Checked ${relative(health.generated_at)} · ${utc(health.generated_at)}` : "Check time unknown";
  const strip = byId("model-health");
  strip.replaceChildren();
  if (!health.checks.length) {
    strip.append(node("p", "empty", "No recognized model checks in the snapshot."));
    return;
  }
  for (const check of health.checks) {
    const item = node("article", "health-item");
    item.append(node("p", "health-model", check.model));
    const meta = node("div", "health-meta");
    meta.append(
      node("span", "", check.provider || "provider unknown"),
      node("span", `badge ${check.status}`, check.status),
    );
    item.append(meta);
    strip.append(item);
  }
}

function updateFreshness(generatedAt) {
  const generated = parseTime(generatedAt);
  const warning = byId("warning");
  byId("freshness").textContent = generated
    ? `Generated ${relative(generatedAt)} · ${utc(generatedAt)}` : "Generation time unknown";
  if (!generated || Date.now() - generated.getTime() > STALE_MS) {
    warning.hidden = false;
    warning.textContent = generated
      ? `Stale data: this snapshot is ${relative(generatedAt)}. The dashboard pipeline may need attention.`
      : "Data freshness is unknown. The dashboard pipeline may need attention.";
  } else {
    warning.hidden = true;
    warning.textContent = "";
  }
}

// --- Agent-run observability (issue #246): cache effectiveness, per-lane run health + top defer
// reasons, queue/lease/review flow, and auto-fixer trigger fires. Consumes the OPTIONAL
// `observability` key of data.json — dashboard-gen validates + salts it server-side from the
// collector's ledger snapshot (data/observability.json on the ledger branch; decision 22: no raw
// account handles anywhere). Absent key => the whole section stays hidden; it never blocks the
// rest of the dashboard. All identifiers here are obs-prefixed so this panel composes with other
// independently-built panels in this file. -------------------------------------------------------
const OBS_DEFAULT_THRESHOLDS = {
  workflow_failure_rate: 0.5, defer_reason_hourly: 4,
  queue_age_clamp_minutes: 10, merge_stall_minutes: 90,
};
const OBS_SALTED_RE = /^[0-9a-f]{8}$/;
const OBS_SPARK_POINTS = 24;
// data.json holds only the current snapshot; trends accumulate client-side across refreshes,
// keyed by generated_at so re-polling an unchanged snapshot is not double-counted.
const obsTrend = { stamp: null, points: [] };

function obsNum(value, fallback = null) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function obsPct(value) {
  const n = obsNum(value);
  return n === null ? "—" : `${(n * 100).toFixed(n * 100 % 1 ? 1 : 0)}%`;
}

function obsThresholds(o) {
  const supplied = o && typeof o.thresholds === "object" && o.thresholds ? o.thresholds : {};
  const out = { ...OBS_DEFAULT_THRESHOLDS };
  for (const key of Object.keys(out)) {
    const value = obsNum(supplied[key]);
    if (value !== null && value >= 0) out[key] = value;
  }
  return out;
}

function obsRecordTrend(o) {
  if (obsTrend.stamp === o.generated_at) return;
  obsTrend.stamp = o.generated_at;
  const cache = o.cache || {};
  const lanes = Array.isArray(o.lanes) ? o.lanes : [];
  const queue = o.flow && Array.isArray(o.flow.queue) ? o.flow.queue : [];
  obsTrend.points.push({
    read: obsNum(cache.prompt_cache_read_fraction_1h),
    warm: obsNum(cache.warm_drain_rate_1h),
    defers: lanes.reduce((sum, lane) => sum + obsNum(lane["1h"] && lane["1h"].defer, 0), 0),
    queue: queue.reduce((sum, row) => sum + obsNum(row.depth, 0), 0),
  });
  if (obsTrend.points.length > OBS_SPARK_POINTS) {
    obsTrend.points.splice(0, obsTrend.points.length - OBS_SPARK_POINTS);
  }
}

function obsSparkline(caption, series, stroke) {
  const values = series.filter((v) => v !== null && Number.isFinite(v));
  const wrap = node("div", "obs-spark-wrap");
  wrap.append(node("p", "obs-spark-caption", caption));
  if (values.length < 2) {
    wrap.append(node("p", "obs-spark-caption muted", "collecting trend…"));
    return wrap;
  }
  const W = 120;
  const H = 26;
  const min = Math.min(...values, 0);
  const span = (Math.max(...values, 0) - min) || 1;
  const step = W / (values.length - 1);
  const y = (v) => H - ((v - min) / span) * (H - 2) - 1;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "obs-spark");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("aria-hidden", "true");
  const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  line.setAttribute("points", values.map((v, i) => `${(i * step).toFixed(1)},${y(v).toFixed(1)}`).join(" "));
  line.setAttribute("fill", "none");
  line.setAttribute("stroke", stroke);
  line.setAttribute("stroke-width", "1.5");
  line.setAttribute("stroke-linejoin", "round");
  line.setAttribute("stroke-linecap", "round");
  const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  dot.setAttribute("cx", ((values.length - 1) * step).toFixed(1));
  dot.setAttribute("cy", y(values[values.length - 1]).toFixed(1));
  dot.setAttribute("r", "2");
  dot.setAttribute("fill", stroke);
  svg.append(line, dot);
  wrap.append(svg);
  return wrap;
}

function obsMetric(label, value, opts = {}) {
  const cell = node("div", "obs-metric");
  cell.append(node("span", "obs-metric-label", label));
  const holder = node("span", `obs-metric-value${opts.tone ? " " + opts.tone : ""}`, value);
  if (opts.sub !== undefined) holder.append(node("span", "obs-metric-sub", opts.sub));
  cell.append(holder);
  return cell;
}

function obsCard(title) {
  const card = node("article", "obs-card");
  card.append(node("h3", "obs-card-title", title));
  return card;
}

function obsRenderTriggers(fires) {
  const host = byId("obs-triggers");
  host.replaceChildren();
  for (const fire of fires) {
    if (!fire || typeof fire !== "object") continue;
    const row = node("div", "obs-trigger-row");
    row.setAttribute("role", "alert");
    row.append(node("span", "obs-trigger-rule", String(fire.rule || "trigger")));
    row.append(node("span", "obs-trigger-summary", String(fire.summary || "")));
    const meta = node("span", "obs-trigger-meta");
    meta.append(node("span", "", fire.fired_at ? `fired ${relative(fire.fired_at)}` : "fire time unknown"));
    if (typeof fire.enqueued_task === "string" && fire.enqueued_task) {
      meta.append(node("span", "obs-chip", `heal task ${fire.enqueued_task}`));
    }
    const links = Array.isArray(fire.evidence) ? fire.evidence : [];
    links.forEach((href, index) => {
      if (typeof href !== "string" || !href.startsWith("https://github.com/")) return;
      const anchor = node("a", "obs-evidence", `evidence ${index + 1}`);
      anchor.href = href;
      anchor.rel = "noopener";
      meta.append(anchor);
    });
    row.append(meta);
    host.append(row);
  }
}

function obsCacheCard(cache) {
  const card = obsCard("Cache effectiveness");
  const grid = node("div", "obs-metric-grid");
  const samples = obsNum(cache.usage_samples_1h, 0);
  grid.append(
    obsMetric("Prompt-cache read", obsPct(cache.prompt_cache_read_fraction_1h),
      { sub: samples ? `${samples} usage sample${samples === 1 ? "" : "s"} / 1h` : "no harness usage signal" }),
    obsMetric("Warm drains", obsPct(cache.warm_drain_rate_1h),
      { sub: `of ${obsNum(cache.drained_1h, 0)} drained / 1h` }),
  );
  card.append(grid);
  const histogram = cache.chain_length_histogram || {};
  const entries = Object.entries(histogram)
    .filter(([, count]) => Number.isInteger(count) && count >= 0);
  if (entries.length) {
    const peak = Math.max(...entries.map(([, count]) => count), 1);
    const bars = node("div", "obs-bars");
    bars.append(node("p", "obs-spark-caption", "cache-chain lengths"));
    for (const [length, count] of entries) {
      const rowEl = node("div", "obs-bar-row");
      rowEl.append(node("span", "obs-bar-label", `×${length}`));
      const track = node("div", "obs-bar-track");
      const fill = node("span", "obs-bar-fill");
      fill.style.width = `${Math.max(4, (count / peak) * 100)}%`;
      track.append(fill);
      rowEl.append(track, node("span", "obs-bar-count", String(count)));
      bars.append(rowEl);
    }
    card.append(bars);
  }
  card.append(
    obsSparkline("read fraction trend", obsTrend.points.map((p) => p.read), "var(--accent)"),
    obsSparkline("warm-drain trend", obsTrend.points.map((p) => p.warm), "var(--accent-2)"),
  );
  return card;
}

function obsHealthCard(lanes, deferReasons, exitClasses, thresholds) {
  const card = obsCard("Agent-run health");
  const table = node("table", "obs-table");
  const head = node("tr");
  for (const title of ["Lane", "1h ✓/✗/defer", "Fail rate 1h", "24h ✓/✗/defer"]) {
    head.append(node("th", "", title));
  }
  table.append(head);
  for (const lane of lanes) {
    const hour = lane["1h"] || {};
    const day = lane["24h"];
    const success = obsNum(hour.success, 0);
    const failure = obsNum(hour.failure, 0);
    const attempts = success + failure;
    const rate = attempts ? failure / attempts : null;
    const row = node("tr");
    row.append(node("td", "obs-lane", String(lane.lane)));
    row.append(node("td", "", `${success} / ${failure} / ${obsNum(hour.defer, 0)}`));
    const tone = rate === null ? "" : rate >= thresholds.workflow_failure_rate ? "bad" : "good";
    row.append(node("td", tone, rate === null ? "—" : obsPct(rate)));
    row.append(node("td", "", day
      ? `${obsNum(day.success, 0)} / ${obsNum(day.failure, 0)} / ${obsNum(day.defer, 0)}` : "—"));
    table.append(row);
  }
  card.append(table);
  if (deferReasons.length) {
    const list = node("div", "obs-reasons");
    list.append(node("p", "obs-spark-caption", "top defer reasons / 1h"));
    for (const item of deferReasons) {
      const rowEl = node("div", "obs-reason-row");
      rowEl.append(node("span", "obs-lane", String(item.reason)));
      const hot = obsNum(item.count, 0) >= thresholds.defer_reason_hourly;
      rowEl.append(node("span", `obs-reason-count${hot ? " bad" : ""}`, `×${obsNum(item.count, 0)}`));
      list.append(rowEl);
    }
    card.append(list);
  }
  if (exitClasses.length) {
    const chips = node("div", "obs-chips");
    for (const row of exitClasses) {
      chips.append(node("span", "obs-chip", `${row.model} · ${row.exit_class} ×${obsNum(row.count, 0)}`));
    }
    card.append(chips);
  }
  card.append(obsSparkline("defers / 1h trend", obsTrend.points.map((p) => p.defers), "var(--warn)"));
  return card;
}

function obsFlowCard(flow, thresholds) {
  const card = obsCard("Queue & flow");
  const queue = Array.isArray(flow.queue) ? flow.queue : [];
  if (queue.length) {
    const list = node("div", "obs-reasons");
    list.append(node("p", "obs-spark-caption", "task queue depth · oldest age"));
    for (const row of queue) {
      const rowEl = node("div", "obs-reason-row");
      rowEl.append(node("span", "obs-lane", `class ${row.class}`));
      const age = obsNum(row.oldest_age_minutes);
      // The anti-starvation clamp guards CLASS-2 (self-healing) age: past it, red.
      const late = age !== null && String(row.class).startsWith("2")
        && age >= thresholds.queue_age_clamp_minutes;
      rowEl.append(node("span", `obs-reason-count${late ? " bad" : ""}`,
        `${obsNum(row.depth, 0)} deep${age === null ? "" : ` · ${age}m`}`));
      list.append(rowEl);
    }
    card.append(list);
  }
  const grid = node("div", "obs-metric-grid");
  const rounds = flow.review_rounds;
  if (rounds) {
    const exhausted = obsNum(rounds.budget_exhausted_1h, 0);
    grid.append(obsMetric("Review rounds",
      `${obsNum(rounds.mean) === null ? "—" : rounds.mean} avg`,
      { sub: `max ${obsNum(rounds.max, 0)} · ${exhausted} budget-exhausted / 1h`,
        tone: exhausted > 0 ? "bad" : "" }));
  }
  const parks = flow.parks_1h;
  if (parks) {
    grid.append(obsMetric("Parked / 1h",
      `${obsNum(parks.needs_user, 0)} user · ${obsNum(parks.needs_orchestrator, 0)} orch`,
      { tone: obsNum(parks.needs_orchestrator, 0) > 0 ? "warn" : "" }));
  }
  const latency = flow.arm_to_merge_minutes_24h;
  if (latency) {
    const p50 = obsNum(latency.p50);
    grid.append(obsMetric("Arm → merge", p50 === null ? "—" : `${p50}m p50`,
      { sub: `${obsNum(latency.p90) === null ? "—" : latency.p90 + "m"} p90 · ${obsNum(latency.samples, 0)} samples / 24h`,
        tone: p50 !== null && p50 >= thresholds.merge_stall_minutes ? "bad" : "" }));
  }
  for (const target of Array.isArray(flow.target_ci_queue) ? flow.target_ci_queue : []) {
    grid.append(obsMetric(`CI queue · ${target.repository}`, String(obsNum(target.depth, 0)),
      { sub: "pending target CI runs" }));
  }
  if (grid.childElementCount) card.append(grid);
  const leases = Array.isArray(flow.leases) ? flow.leases : [];
  if (leases.length) {
    const list = node("div", "obs-reasons");
    list.append(node("p", "obs-spark-caption", "lease utilization / 1h (salted accounts)"));
    for (const lease of leases) {
      // Defense in depth for decision 22: only the salted 8-hex label shape is ever rendered.
      if (typeof lease.label !== "string" || !OBS_SALTED_RE.test(lease.label)) continue;
      const rowEl = node("div", "obs-reason-row");
      rowEl.append(node("span", "obs-lane", `${lease.label}${lease.provider ? ` · ${lease.provider}` : ""}`));
      const meter = node("div", "obs-bar-track wide");
      const used = obsNum(lease.utilization_1h);
      const fill = node("span", `obs-bar-fill${used !== null && used >= 0.85 ? " hot" : ""}`);
      fill.style.width = `${used === null ? 0 : Math.min(100, used * 100)}%`;
      meter.append(fill);
      rowEl.append(meter, node("span", "obs-reason-count", obsPct(lease.utilization_1h)));
      list.append(rowEl);
    }
    card.append(list);
  }
  card.append(obsSparkline("queue depth trend", obsTrend.points.map((p) => p.queue), "var(--accent-2)"));
  return card;
}

function renderObservability(o) {
  const section = byId("obs-section");
  if (!o || typeof o !== "object") {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  obsRecordTrend(o);
  byId("obs-time").textContent = o.generated_at
    ? `Collected ${relative(o.generated_at)} · ${utc(o.generated_at)}` : "Collection time unknown";
  const thresholds = obsThresholds(o);
  obsRenderTriggers(Array.isArray(o.trigger_fires) ? o.trigger_fires : []);
  const grid = byId("obs-grid");
  grid.replaceChildren();
  if (o.cache && typeof o.cache === "object") grid.append(obsCacheCard(o.cache));
  const lanes = Array.isArray(o.lanes) ? o.lanes : [];
  if (lanes.length) {
    grid.append(obsHealthCard(
      lanes,
      Array.isArray(o.defer_reasons_1h) ? o.defer_reasons_1h : [],
      Array.isArray(o.model_exit_classes_1h) ? o.model_exit_classes_1h : [],
      thresholds,
    ));
  }
  if (o.flow && typeof o.flow === "object") grid.append(obsFlowCard(o.flow, thresholds));
  if (!grid.childElementCount) {
    grid.append(node("p", "empty subtle", "Observability snapshot has no renderable groups yet."));
  }
}

function render(data) {
  renderRepositoryAgents(data.active_by_repository, data.fleet.active_agents);
  renderSummary(data);
  renderProviderQuota(data.provider_quota, data.generated_at);
  renderAccounts(data.accounts || []);
  renderOutcomes(data.fleet.dispatch_outcomes || []);
  renderHealth(data.model_health);
  renderObservability(data.observability);
  updateFreshness(data.generated_at);
}

async function refresh() {
  try {
    const response = await fetch(`data.json?t=${Date.now()}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (data.schema !== "account-fleet-dashboard/v1") throw new Error("unsupported data schema");
    render(data);
  } catch (error) {
    const warning = byId("warning");
    warning.hidden = false;
    warning.textContent = `Dashboard refresh failed: ${error.message}. The last rendered snapshot remains visible.`;
  }
}

refresh();
setInterval(refresh, REFRESH_MS);
