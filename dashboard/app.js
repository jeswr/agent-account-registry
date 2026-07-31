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

// Issue #71: a reset stamp is the only FORWARD-looking instant on this page — every other stamp
// (generated_at, attempted_at, fired_at, an outcome's `at`) is an observation that already
// happened, so `relative()`'s "N minutes ago" is correct for those and a lie for a reset. The page
// polls a data.json that dashboard-gen rebuilds far less often than REFRESH_MS, so a reset stamp
// crossing `now` between two builds is ORDINARY, not exceptional — and when it does, "next reset 6
// minutes ago" is not a reset time at all. What an elapsed stamp means is the opposite of what the
// sentence says: that window has ALREADY refilled and the utilization beside it was measured
// before the refill. Every caller composes its own sentence from this one predicate rather than
// re-deriving the comparison, and it is evaluated at RENDER time (not at generation time) because
// the stamp elapses while the page is open, with no new data.json involved.
function hasElapsed(value) {
  const date = parseTime(value);
  return date !== null && date.getTime() <= Date.now();
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
  // Issue #374: `capacity[provider]` is a BOOLEAN — whether the allocator would find an eligible
  // account for this provider right now — not the `eligible / total` account census it used to be.
  for (const [provider, hasCapacity] of providers) {
    const line = node("div", "provider-line");
    line.append(node("span", "", provider),
      node("strong", "", hasCapacity ? "available" : "none free"));
    lines.append(line);
  }
  if (!providers.length) lines.append(node("p", "summary-meta", "No provider records"));
  capacity.append(lines);
  // "none free" is exactly what a failed probe used to overstate in the other direction (issue
  // #580): with nothing measured EVERY provider reads unavailable, which alone looks like a
  // fleet-wide outage. Say which of the two it is, right where the misleading value is rendered.
  if (data.usage_probe && typeof data.usage_probe === "object"
      && data.usage_probe.measured !== true) {
    capacity.append(node("p", "summary-meta", "Eligible capacity unmeasured — see the notice above"));
  }
  summary.append(capacity);
  summary.append(summaryCard(
    "Last dispatch sweep", data.fleet.last_sweep_at ? relative(data.fleet.last_sweep_at) : "unknown",
    data.fleet.last_sweep_at ? utc(data.fleet.last_sweep_at) : "No completed sweep data",
  ));
  const probe = usageProbeCard(data.usage_probe);
  if (probe) summary.append(probe);
  summary.append(summaryCard("Data freshness", relative(data.generated_at), utc(data.generated_at)));
}

// --- Usage-probe freshness (issue #219). The probe job's secret materialization and probe steps
// are continue-on-error, and a failed probe publishes an EMPTY snapshot; without this marker the
// page could not distinguish "nothing is running" from "nothing was measured", so a broken probe
// read as a fully idle, fully available fleet. dashboard-gen only sets `measured` for an explicit,
// FRESH `ok` outcome, and renders every account unknown / zero eligible capacity otherwise — this
// card says WHY. An absent key (older data.json) simply hides the card. --------------------------
function usageProbeCard(probe) {
  if (!probe || typeof probe !== "object") return null;
  const measured = probe.measured === true;
  const age = num(probe.age_seconds);
  const detail = typeof probe.detail === "string" && probe.detail ? ` · ${probe.detail}` : "";
  const card = summaryCard(
    "Usage probe",
    probe.attempted_at ? relative(probe.attempted_at) : "never recorded",
    measured
      ? `Measured ok · ${utc(probe.attempted_at)}`
      : `NOT MEASURED — ${String(probe.outcome || "unknown")}${probe.stale ? " · stale" : ""}${detail}`
        + `${age === null ? "" : ` · ${age}s old`}`
        + " · availability shown as unknown, capacity not counted as free",
  );
  if (!measured) card.classList.add("degraded");
  return card;
}

// Issue #374: the per-account cards (salted label, availability badge, active-agent count,
// weekly reset and live per-window utilization) are GONE, together with renderWindow /
// renderWeeklyReset / accountCard / renderAccounts. dashboard-gen no longer publishes an
// `accounts` array at all, so there is nothing left for them to render — the per-provider section
// below is the whole quota surface now.

// --- Provider quota: per-provider AGGREGATE headroom, computed server-side by
// dashboard-gen._provider_quota from the signals that actually exist — live per-window utilization
// probes where the provider exposes them (anthropic), and only availability + reactive backoff
// where it does not (probe-exempt openai). Accounts the fail-closed probe OMITTED are never
// rendered free — dispatch treats that omission as unavailable (sol finding 2, PR #281); so are
// PARTIAL probe entries (status-only / one window without the other), which dispatch and
// usage-alert equally reject (sol finding 1, PR #281 fix round 3) and which contribute NOTHING to
// the aggregate (fix round 4).
//
// Issue #374 MINIMIZED what crosses to the page. The card used to print the fleet census —
// "3 accounts · 1 free · 1 capped · 1 unreported", a "single account" badge, and per-window
// "0.85 of 2 account-windows free" plus "≈200 provider limit-units left (limits known for 1/2)".
// Every one of those numbers counted accounts out loud on a public page. The generator now sends
// a `headroom` WORD (available/capped/unknown/unavailable — the same predicate the allocator uses,
// so the page still cannot advertise capacity dispatch would refuse) and a per-window
// `remaining_fraction` in [0,1] (the MEAN across reporting accounts, invariant under fleet size).
// An absent `provider_quota` key (older data.json) hides the whole section. -----------------------
const QUOTA_HEADROOM_TEXT = {
  available: "capacity available",
  capped: "all quota spent — waiting on a reset",
  unknown: "no usable measurement — treated unavailable by dispatch",
  unavailable: "no usable account for this provider",
};

function quotaWindowRow(windowData) {
  const wrap = node("div", "window");
  const head = node("div", "window-head");
  const fraction = typeof windowData.remaining_fraction === "number"
    && Number.isFinite(windowData.remaining_fraction)
    ? Math.min(1, Math.max(0, windowData.remaining_fraction)) : null;
  head.append(
    node("span", "window-name", windowData.name),
    node("span", "window-value", fraction === null
      ? "unknown"
      : `${Math.round(fraction * 100)}% of this window's quota left`),
  );
  const meter = node("div", "meter");
  meter.setAttribute("role", "progressbar");
  meter.setAttribute("aria-label", `${windowData.name} aggregate remaining quota`);
  if (fraction !== null) {
    meter.setAttribute("aria-valuenow", String(Math.round(fraction * 100)));
    meter.setAttribute("aria-valuemin", "0");
    meter.setAttribute("aria-valuemax", "100");
    const fill = node("span", fraction <= 0.15 ? "high" : "");
    fill.style.width = `${fraction * 100}%`;
    meter.append(fill);
  }
  const notes = [];
  const soonest = windowData.soonest_reset;
  const oldest = windowData.oldest_reset;
  if (soonest) {
    // [#71] An elapsed soonest reset also dates the percentage rendered above it: the meter is
    // left alone (a refilled window only ever has MORE quota than shown, so the reading stays
    // conservative and the page still cannot advertise capacity dispatch would refuse) but it must
    // not be read as current.
    notes.push(hasElapsed(soonest)
      ? `reset was due ${relative(soonest)} — already refilled, the quota above predates it`
      : `next reset ${relative(soonest)}`);
    if (oldest && oldest !== soonest) {
      notes.push(hasElapsed(oldest)
        ? `all refilled by ${relative(oldest)}` : `last reset ${relative(oldest)}`);
    }
  }
  wrap.append(head, meter, node("p", "reset", notes.length ? notes.join(" · ") : "Reset unknown"));
  return wrap;
}

function providerQuotaCard(row) {
  const card = node("article", "account-card quota-card");
  const top = node("div", "card-top");
  top.append(node("h4", "quota-provider", String(row.provider || "unknown")));
  const headroom = Object.prototype.hasOwnProperty.call(QUOTA_HEADROOM_TEXT, row.headroom)
    ? row.headroom : "unknown";
  const badges = node("div", "badges");
  badges.append(node("span", `badge ${headroom}`, headroom));
  top.append(badges);
  const windows = node("div", "window-list");
  const windowRows = Array.isArray(row.windows) ? row.windows : [];
  for (const windowData of windowRows) windows.append(quotaWindowRow(windowData));
  if (!windowRows.length) {
    windows.append(node("p", "quota-note",
      "Remaining quota is not observable for this provider — the headroom state above is the only real signal."));
  }
  card.append(top, node("p", "quota-counts", QUOTA_HEADROOM_TEXT[headroom]), windows);
  if (row.soonest_reset) {
    // [#71] Same predicate, provider-wide: `oldest_reset` is when the LAST known window refills, so
    // once it has elapsed nothing on this card is waiting on a reset any more — saying it "resets
    // by" a past instant reads as a pending refill that has in fact already happened.
    card.append(node("p", "quota-note", (hasElapsed(row.soonest_reset)
      ? `Soonest known reset was due ${relative(row.soonest_reset)}`
      : `Soonest known reset ${relative(row.soonest_reset)}`)
      + (hasElapsed(row.oldest_reset)
        ? ` · all known windows have refilled (by ${utc(row.oldest_reset)})`
        : ` · all known windows reset by ${utc(row.oldest_reset)}`)));
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

// Issue #323: the per-lane decomposition of one dispatch tick (worker/review/fix/disarm ×
// planned/launched/deferred/error), as emitted by dispatch-claim and carried through
// dashboard-gen's `_dispatch_lane_rows`. All four counts render UNCONDITIONALLY, including zeroes:
// a lane whose numbers vanish when they go quiet is exactly the row an operator interrogates after
// a stall. The red/amber tone is `lane.state`, decided once in the generator — this function
// renders the verdict and never recomputes it, so there is no second copy of the stall rule here.
function laneCell(lanes) {
  const cell = node("td", "lane-cell");
  if (!Array.isArray(lanes) || !lanes.length) {
    cell.textContent = "—";
    return cell;
  }
  for (const lane of lanes) {
    const state = LANE_STATES.has(lane.state) ? lane.state : "unknown";
    const chip = node("span", "lane-light");
    chip.append(node("span", `lane-dot ${state}`));
    chip.append(node("strong", "", String(lane.lane)));
    chip.append(document.createTextNode(
      ` ${num(lane.planned, 0)}p ${num(lane.launched, 0)}l ` +
      `${num(lane.deferred, 0)}d ${num(lane.error, 0)}e`));
    cell.append(chip);
  }
  return cell;
}

function renderOutcomes(outcomes) {
  const body = byId("outcomes");
  body.replaceChildren();
  if (!outcomes.length) {
    const row = node("tr");
    const cell = node("td", "", "No dispatch history is available.");
    cell.colSpan = 5;
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
      laneCell(outcome.lanes),
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
  const notices = [];
  if (!generated || Date.now() - generated.getTime() > STALE_MS) {
    notices.push(generated
      ? `Stale data: this snapshot is ${relative(generatedAt)}. The dashboard pipeline may need attention.`
      : "Data freshness is unknown. The dashboard pipeline may need attention.");
  }
  // Issue #219: a freshly GENERATED page can still carry an unmeasured fleet — the generation
  // stamp above says only that the build ran, never that the probe succeeded. Say so explicitly,
  // because "generated 2 minutes ago" was exactly what made a failed probe look healthy.
  if (probe && typeof probe === "object" && probe.measured !== true) {
    notices.push(`Usage probe did not measure the fleet (${String(probe.outcome || "unknown")}`
      + `${probe.stale ? ", stale" : ""}): account availability and provider capacity below are`
      + " shown as unknown, not as free capacity.");
  }
  warning.hidden = notices.length === 0;
  // Staleness and the probe verdict are INDEPENDENT degradations (issue #580) and both can fire at
  // once — a failed probe still publishes a FRESH generated_at, so neither notice implies the
  // other. One `.warning-line` paragraph each (styles.css spaces them); run together in a single
  // text blob the two read as one confused sentence.
  warning.replaceChildren(...notices.map((notice) => node("p", "warning-line", notice)));
}

// --- Throughput panel (backlog-vs-drain). Consumes site/metrics.json, emitted by the separate
// metrics collector workflow (see the observability-metrics PR). It is optional: if the file is
// absent (metrics workflow not deployed yet) the panel simply stays hidden — it never blocks the
// rest of the dashboard. --------------------------------------------------------------------------

const REPO_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const LANE_STATES = new Set(["ok", "idle", "stalled", "unknown"]);
const SPARK_KEYS = ["net_pr_flow", "issues_ready", "prs_open"];
// The published site/metrics.json holds only the CURRENT snapshot (the ring history lives on the
// ledger branch and is not served). We accumulate our own bounded, per-target trend buffer across
// refreshes — keyed by the snapshot's generated_at so a repeated poll of an unchanged snapshot is
// not double-counted.
const SPARK_HISTORY = 24;
const trendBuffers = new Map();

function num(value, fallback = null) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function fmtRate(value) {
  const n = num(value);
  if (n === null) return "—";
  return `${n >= 0 ? "" : ""}${n.toFixed(n % 1 ? 1 : 0)}`;
}

function fmtSigned(value) {
  const n = num(value);
  if (n === null) return "—";
  return `${n > 0 ? "+" : ""}${n.toFixed(n % 1 ? 1 : 0)}`;
}

function recordTrend(targets, stamp) {
  const seen = new Set();
  for (const [repo, metrics] of Object.entries(targets)) {
    if (!REPO_RE.test(repo)) continue;
    seen.add(repo);
    let buffer = trendBuffers.get(repo);
    if (!buffer) { buffer = { stamp: null, points: [] }; trendBuffers.set(repo, buffer); }
    if (buffer.stamp === stamp) continue; // same snapshot polled again — do not duplicate
    buffer.stamp = stamp;
    const point = {};
    for (const key of SPARK_KEYS) point[key] = num(metrics[key]);
    buffer.points.push(point);
    if (buffer.points.length > SPARK_HISTORY) buffer.points.splice(0, buffer.points.length - SPARK_HISTORY);
  }
  for (const repo of [...trendBuffers.keys()]) if (!seen.has(repo)) trendBuffers.delete(repo);
}

function sparkline(series, { colorForLast } = {}) {
  const values = series.filter((v) => v !== null && Number.isFinite(v));
  const wrap = node("div", "spark-wrap");
  if (values.length < 2) {
    wrap.append(node("p", "spark-caption", "collecting trend…"));
    return wrap;
  }
  const W = 120;
  const H = 30;
  const min = Math.min(...values, 0);
  const max = Math.max(...values, 0);
  const span = max - min || 1;
  const step = W / (values.length - 1);
  const y = (v) => H - ((v - min) / span) * H;
  const points = values.map((v, i) => `${(i * step).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const last = values[values.length - 1];
  const stroke = colorForLast ? colorForLast(last) : "var(--accent)";
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "spark");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("aria-hidden", "true");
  if (min < 0 && max > 0) {
    const zero = document.createElementNS("http://www.w3.org/2000/svg", "line");
    zero.setAttribute("x1", "0"); zero.setAttribute("x2", String(W));
    zero.setAttribute("y1", y(0).toFixed(1)); zero.setAttribute("y2", y(0).toFixed(1));
    zero.setAttribute("stroke", "var(--line)"); zero.setAttribute("stroke-width", "1");
    svg.append(zero);
  }
  const path = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  path.setAttribute("points", points);
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", stroke);
  path.setAttribute("stroke-width", "1.5");
  path.setAttribute("stroke-linejoin", "round");
  path.setAttribute("stroke-linecap", "round");
  svg.append(path);
  const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  dot.setAttribute("cx", ((values.length - 1) * step).toFixed(1));
  dot.setAttribute("cy", y(last).toFixed(1));
  dot.setAttribute("r", "2");
  dot.setAttribute("fill", stroke);
  svg.append(dot);
  wrap.append(svg);
  return wrap;
}

function metricCell(label, value, opts = {}) {
  const cell = node("div", "metric");
  cell.append(node("span", "metric-label", label));
  const v = node("span", `metric-value${opts.tone ? " " + opts.tone : ""}`, value);
  if (opts.sub !== undefined) v.append(node("span", "metric-sub", opts.sub));
  cell.append(v);
  return cell;
}

function flowIndicator(net) {
  const n = num(net);
  const badge = node("span", "flow-badge");
  if (n === null) { badge.classList.add("steady"); badge.textContent = "flow unknown"; return badge; }
  if (n > 0) {
    badge.classList.add("growing");
    badge.textContent = `▲ backlog growing +${n.toFixed(n % 1 ? 1 : 0)}/hr`;
  } else if (n < 0) {
    badge.classList.add("draining");
    badge.textContent = `▼ draining ${n.toFixed(n % 1 ? 1 : 0)}/hr`;
  } else {
    badge.classList.add("steady");
    badge.textContent = "● steady 0/hr";
  }
  return badge;
}

function laneLight(health) {
  const state = LANE_STATES.has(health) ? health : "unknown";
  const wrap = node("span", "lane-light");
  wrap.append(node("span", `lane-dot ${state}`));
  wrap.append(document.createTextNode("Review lane "));
  wrap.append(node("strong", "", state));
  return wrap;
}

function throughputCard(repo, m, trend) {
  const card = node("article", "throughput-card");
  const top = node("div", "card-top");
  top.append(node("h3", "throughput-target", repo));
  top.append(flowIndicator(m.net_pr_flow));
  card.append(top);

  const drained = num(m.issues_closed_1h, 0);
  const grid = node("div", "metric-grid");
  grid.append(
    metricCell("Issues open", String(num(m.issues_open, 0))),
    metricCell("Ready to drain", String(num(m.issues_ready, 0))),
    metricCell("Drained / 1h", String(drained), { tone: drained > 0 ? "good" : "" }),
    metricCell("PRs open", String(num(m.prs_open, 0)), { sub: `${num(m.prs_draft, 0)} draft` }),
    metricCell("review:changes", String(num(m.review_changes_backlog, 0)),
      { tone: num(m.review_changes_backlog, 0) > 0 ? "bad" : "" }),
    metricCell("needs:user", String(num(m.needs_user_parked, 0))),
  );
  card.append(grid);

  const rate = node("div", "rate-row");
  const openCell = node("div", "rate-cell");
  openCell.append(node("span", "rate-label", "PR open-rate /hr"), node("span", "rate-value", fmtRate(m.pr_open_rate)));
  const closeCell = node("div", "rate-cell close");
  closeCell.append(node("span", "rate-label", "close+merge /hr"), node("span", "rate-value", fmtRate(m.pr_close_rate)));
  rate.append(openCell, node("span", "rate-arrow", "vs"), closeCell);
  card.append(rate);

  const foot = node("div", "throughput-foot");
  foot.append(laneLight(m.review_lane_health));
  const merged = num(m.prs_merged_1h, 0);
  foot.append(node("span", "lane-light", `${merged} merged / 1h · ${num(m.prs_merged_24h, 0)} / 24h`));
  card.append(foot);

  // Sparkline for net PR flow (the headline backlog-vs-drain signal), colored by direction.
  if (trend && trend.points.length) {
    const netSeries = trend.points.map((p) => p.net_pr_flow);
    const spark = sparkline(netSeries, {
      colorForLast: (v) => (v > 0 ? "var(--bad)" : v < 0 ? "var(--good)" : "var(--muted)"),
    });
    spark.prepend(node("p", "spark-caption", "net PR flow trend"));
    card.append(spark);
  }
  return card;
}

function renderThroughput(metrics) {
  const section = byId("throughput-section");
  if (!metrics || !metrics.targets || typeof metrics.targets !== "object") {
    section.hidden = true;
    return;
  }
  const entries = Object.entries(metrics.targets).filter(([repo]) => REPO_RE.test(repo));
  if (!entries.length) { section.hidden = true; return; }
  section.hidden = false;

  recordTrend(metrics.targets, metrics.generated_at);

  byId("throughput-time").textContent = metrics.generated_at
    ? `Snapshot ${relative(metrics.generated_at)} · ${utc(metrics.generated_at)}`
    : "Snapshot time unknown";

  const alertHost = byId("throughput-alerts");
  alertHost.replaceChildren();
  const alerts = Array.isArray(metrics.alerts) ? metrics.alerts.filter((a) => a && a.fire !== false) : [];
  for (const alert of alerts) {
    const row = node("div", "alert-row");
    row.setAttribute("role", "alert");
    row.append(node("span", "alert-class", String(alert.classification || "alert")));
    row.append(node("span", "alert-summary", String(alert.summary || "")));
    if (alert.target) row.append(node("span", "alert-target", String(alert.target)));
    alertHost.append(row);
  }

  const host = byId("throughput-targets");
  host.replaceChildren();
  entries.sort(([a], [b]) => a.localeCompare(b));
  for (const [repo, m] of entries) {
    if (!m || typeof m !== "object") continue;
    host.append(throughputCard(repo, m, trendBuffers.get(repo)));
  }
}

async function refreshThroughput() {
  try {
    const response = await fetch(`metrics.json?t=${Date.now()}`, { cache: "no-store" });
    if (!response.ok) { renderThroughput(null); return; }
    const metrics = await response.json();
    if (typeof metrics !== "object" || !metrics || !metrics.targets) { renderThroughput(null); return; }
    renderThroughput(metrics);
  } catch (error) {
    // The throughput panel is optional and independently sourced — a fetch/parse failure hides it
    // rather than tripping the dashboard-wide warning banner.
    renderThroughput(null);
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
  // Issue #374: this used to be one bar PER SALTED ACCOUNT — a per-account row array by another
  // name, whose length was the fleet size and whose labels were stable across builds. The
  // generator now sends only the mean and max of the reported utilizations, which is what the
  // load-balance question ("is one account carrying the fleet?") actually needs.
  const leaseUtilization = flow.lease_utilization_1h;
  if (leaseUtilization && typeof leaseUtilization === "object") {
    const list = node("div", "obs-reasons");
    list.append(node("p", "obs-spark-caption", "lease utilization / 1h (across the fleet)"));
    for (const [caption, value] of [["mean", leaseUtilization.mean],
                                    ["busiest", leaseUtilization.max]]) {
      const rowEl = node("div", "obs-reason-row");
      rowEl.append(node("span", "obs-lane", caption));
      const meter = node("div", "obs-bar-track wide");
      const used = obsNum(value);
      const fill = node("span", `obs-bar-fill${used !== null && used >= 0.85 ? " hot" : ""}`);
      fill.style.width = `${used === null ? 0 : Math.min(100, used * 100)}%`;
      meter.append(fill);
      rowEl.append(meter, node("span", "obs-reason-count", obsPct(value)));
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
  renderOutcomes(data.fleet.dispatch_outcomes || []);
  renderHealth(data.model_health);
  renderObservability(data.observability);
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
refreshThroughput();
setInterval(refresh, REFRESH_MS);
setInterval(refreshThroughput, REFRESH_MS);
