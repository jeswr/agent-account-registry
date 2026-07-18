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
  const probe = data.usage_probe;
  if (probe && typeof probe.status === "string") {
    summary.append(summaryCard(
      "Usage probe", probe.status,
      probe.at ? `Measured ${relative(probe.at)} · ${utc(probe.at)}` : "No measurement timestamp",
    ));
  }
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

function updateFreshness(generatedAt, probe) {
  const generated = parseTime(generatedAt);
  const warning = byId("warning");
  byId("freshness").textContent = generated
    ? `Generated ${relative(generatedAt)} · ${utc(generatedAt)}` : "Generation time unknown";
  const messages = [];
  if (!generated || Date.now() - generated.getTime() > STALE_MS) {
    messages.push(generated
      ? `Stale data: this snapshot is ${relative(generatedAt)}. The dashboard pipeline may need attention.`
      : "Data freshness is unknown. The dashboard pipeline may need attention.");
  }
  if (probe && typeof probe.status === "string" && probe.status !== "ok") {
    messages.push(`Usage probe ${probe.status}: quota utilization was not measured for this `
      + "snapshot — unmeasured accounts are shown as unknown and excluded from eligible capacity.");
  }
  warning.hidden = !messages.length;
  warning.textContent = messages.join(" ");
}

function render(data) {
  renderRepositoryAgents(data.active_by_repository, data.fleet.active_agents);
  renderSummary(data);
  renderAccounts(data.accounts || []);
  renderOutcomes(data.fleet.dispatch_outcomes || []);
  renderHealth(data.model_health);
  updateFreshness(data.generated_at, data.usage_probe);
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
