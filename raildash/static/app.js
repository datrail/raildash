/* RailDash front end.
 *
 * One rule governs everything below: captured traffic is untrusted input. A
 * path, a header value or a response body is whatever the agent's counterparty
 * sent, and an agent under prompt injection is precisely the case this
 * dashboard exists to look at. So every captured value reaches the page
 * through textContent or a DOM node — never innerHTML, never a template
 * string spliced into markup. The one exception would be nothing.
 */

"use strict";

const state = {
  sessionId: null,
  host: null,
  offset: 0,
  limit: 100,
  total: 0,
  driftLeft: null,
  driftRight: null,
};

const $ = (id) => document.getElementById(id);
const staticDemo = window.RAIL_DASH_STATIC_DEMO === true;
let staticDataPromise = null;

/* --------------------------------------------------------------- utilities */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function fmtInt(n) {
  return typeof n === "number" ? n.toLocaleString() : "—";
}

function fmtMs(ms, compact) {
  if (typeof ms !== "number" || Number.isNaN(ms)) return "—";
  const sp = compact ? "" : " ";
  if (ms < 1000) return `${Math.round(ms)}${sp}ms`;
  return `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)}${sp}s`;
}

function fmtBytes(n) {
  if (typeof n !== "number" || Number.isNaN(n)) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${i === 0 ? v : v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso).slice(0, 19);
  return d.toLocaleTimeString([], { hour12: false }) +
    "." + String(d.getMilliseconds()).padStart(3, "0");
}

function statusPill(code) {
  if (code === null || code === undefined) {
    const p = el("span", "pill pill-none", "—");
    p.title = "No response was paired with this request";
    return p;
  }
  let cls = "pill-ok";
  if (code >= 500) cls = "pill-fail";
  else if (code >= 400) cls = "pill-fail";
  else if (code >= 300) cls = "pill-warn";
  return el("span", `pill ${cls}`, code);
}

async function getJSON(path, params) {
  if (staticDemo) return getStaticJSON(path, params || {});
  const url = new URL(path, window.location.origin);
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== "" && v !== false) {
      url.searchParams.set(k, v);
    }
  });
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function staticFixtureData() {
  if (!staticDataPromise) {
    staticDataPromise = fetch("./fixture-data.json").then((response) => {
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      return response.json();
    });
  }
  return staticDataPromise;
}

function filterStaticInteractions(items, params) {
  const filtered = items.filter((row) => {
    if (params.session_id && row.session_id !== params.session_id) return false;
    if (params.host && row.host !== params.host) return false;
    if (params.method && row.method !== params.method) return false;
    if (params.status_class && String(row.status_code || "")[0] !== params.status_class) return false;
    if (params.errors_only && !(row.status_code >= 400)) return false;
    if (params.q) {
      const needle = String(params.q).toLowerCase();
      if (!String(row.host || "").toLowerCase().includes(needle) &&
          !String(row.path || "").toLowerCase().includes(needle)) return false;
    }
    return true;
  });
  const offset = Number(params.offset || 0);
  const limit = Number(params.limit || 100);
  return { total: filtered.length, items: filtered.slice(offset, offset + limit) };
}

async function getStaticJSON(path, params) {
  const data = await staticFixtureData();
  if (path === "/api/sessions") return data.sessions;
  if (path === "/api/overview") return data.overview;
  if (path === "/api/profile") return data.profile;
  if (path === "/api/filters") return data.filters;
  if (path === "/api/interactions") {
    return filterStaticInteractions(data.interactions, params);
  }
  if (path.startsWith("/api/interactions/")) {
    const rowId = path.slice(path.lastIndexOf("/") + 1);
    const detail = data.details[rowId];
    if (detail) return detail;
  }
  throw new Error(`Static fixture has no response for ${path}`);
}

function setConn(stateName, text) {
  const node = $("conn");
  node.dataset.state = stateName;
  $("conn-text").textContent = text;
}

/* ----------------------------------------------------------------- filters */

function filterParams() {
  return {
    session_id: state.sessionId,
    host: state.host,
    method: $("f-method").value,
    status_class: $("f-status").value,
    q: $("f-q").value.trim(),
    errors_only: $("f-errors").checked,
  };
}

/* ---------------------------------------------------------------- sessions */

async function loadSessions() {
  const sessions = await getJSON("/api/sessions");
  const list = $("sessions");
  list.replaceChildren();
  $("session-count").textContent = sessions.length ? String(sessions.length) : "0";
  $("rail-empty").hidden = sessions.length > 0;

  if (sessions.length && state.sessionId === null) {
    state.sessionId = sessions[0].session_id;
  }
  // The selected session may have come from a database that has since been
  // replaced under us; fall back rather than filtering everything to nothing.
  if (state.sessionId && !sessions.some((s) => s.session_id === state.sessionId)) {
    state.sessionId = sessions.length ? sessions[0].session_id : null;
  }

  sessions.forEach((s) => {
    const li = el("li");
    const btn = el("button", "session");
    btn.type = "button";
    btn.setAttribute("aria-current", String(s.session_id === state.sessionId));

    btn.append(el("span", "session-name", s.session_id));

    const meta = el("span", "session-meta");
    meta.append(el("span", null, `${fmtInt(s.interaction_count)} calls`));
    if (s.error_count > 0) {
      meta.append(el("span", "bad", `${fmtInt(s.error_count)} failed`));
    }
    btn.append(meta);

    btn.addEventListener("click", () => {
      state.sessionId = s.session_id;
      state.host = null;
      state.offset = 0;
      refresh();
    });

    li.append(btn);
    list.append(li);
  });
  syncDriftSelectors(sessions);
}

function syncDriftSelectors(sessions) {
  const ids = sessions.map((session) => session.session_id);
  if (!ids.includes(state.driftRight)) state.driftRight = ids[0] || null;
  if (!ids.includes(state.driftLeft)) state.driftLeft = ids[1] || ids[0] || null;

  [["drift-left", state.driftLeft], ["drift-right", state.driftRight]].forEach(
    ([id, selected]) => {
      const select = $(id);
      select.replaceChildren();
      ids.forEach((sessionId) => {
        const option = el("option", null, sessionId);
        option.value = sessionId;
        select.append(option);
      });
      select.value = selected || "";
      select.disabled = ids.length === 0;
    }
  );
}

/* ---------------------------------------------------------------- overview */

async function loadOverview() {
  const data = await getJSON("/api/overview", { session_id: state.sessionId });
  const t = data.totals || {};

  $("stat-interactions").textContent = fmtInt(t.interactions);
  $("stat-hosts").textContent = fmtInt(t.hosts);
  $("stat-tools").textContent = fmtInt(t.tool_calls);

  const errors = t.errors || 0;
  $("stat-errors").textContent = fmtInt(errors);
  $("tile-errors").dataset.alert = String(errors > 0);
  $("stat-error-rate").textContent = t.interactions
    ? `${((errors / t.interactions) * 100).toFixed(errors ? 1 : 0)}% of calls`
    : "";

  // Average, not p50: SQLite has no percentile aggregate, and computing one
  // from the visible page would label a page statistic as a total. The tile
  // says avg because that is what it is.
  // Compact here: "836 ms / 2.41 s" wraps to two lines in a tile this width,
  // and a wrapped statistic reads as two numbers rather than one pair.
  $("stat-latency").textContent =
    `${fmtMs(t.avg_latency_ms, true)} / ${fmtMs(t.max_latency_ms, true)}`;

  const total = (t.request_bytes || 0) + (t.response_bytes || 0);
  $("stat-bytes").textContent = fmtBytes(total);
  $("stat-bytes-note").textContent =
    `${fmtBytes(t.request_bytes || 0)} out · ${fmtBytes(t.response_bytes || 0)} in`;

  renderHosts(data.hosts || []);
}

function profileValues(title, items) {
  const group = el("section", "profile-group");
  group.append(el("h3", null, title));
  const values = el("div", "profile-values");
  if (!items.length) {
    values.append(el("span", "muted", "None observed"));
  }
  items.forEach((item) => {
    const chip = el("span", "profile-chip");
    chip.append(el("span", "profile-value", item.value));
    chip.append(el("span", "profile-count", item.count));
    values.append(chip);
  });
  group.append(values);
  return group;
}

async function loadProfile() {
  const grid = $("profile-grid");
  const download = $("profile-download");
  grid.replaceChildren();
  if (!state.sessionId) {
    grid.append(el("p", "muted", "Select a captured session."));
    download.setAttribute("aria-disabled", "true");
    download.removeAttribute("href");
    return;
  }

  const path = `/api/profile?session_id=${encodeURIComponent(state.sessionId)}`;
  const profile = await getJSON("/api/profile", { session_id: state.sessionId });
  const observed = profile.observed || {};
  download.href = staticDemo ? "./profile.json" : path;
  download.removeAttribute("aria-disabled");

  const facts = el("section", "profile-group profile-facts");
  facts.append(el("h3", null, "Capture summary"));
  const summary = el("dl", "profile-summary");
  [
    ["Errors", `${fmtInt(observed.error_count)} · ${((observed.error_rate || 0) * 100).toFixed(1)}%`],
    ["x-rail", observed.x_rail && observed.x_rail.present
      ? `present on ${fmtInt(observed.x_rail.interaction_count)} calls`
      : "not observed"],
  ].forEach(([label, value]) => {
    summary.append(el("dt", null, label));
    summary.append(el("dd", null, value));
  });
  facts.append(summary);
  grid.append(facts);
  grid.append(profileValues("Hosts", observed.hosts || []));
  grid.append(profileValues("Methods", observed.methods || []));
  grid.append(profileValues("Tools", observed.tool_names || []));
  grid.append(profileValues("Models", observed.models || []));
}

function changedValues(before, after) {
  const previous = new Set((before || []).map((item) => item.value));
  const current = new Set((after || []).map((item) => item.value));
  return {
    added: [...current].filter((item) => !previous.has(item)).sort(),
    removed: [...previous].filter((item) => !current.has(item)).sort(),
  };
}

function driftLabels(title, change, incomplete) {
  const section = el("section", "drift-group");
  section.append(el("h3", null, title));
  if (incomplete) {
    section.append(el("p", "note", "Comparison incomplete because one or both profiles truncated this dimension."));
    return section;
  }
  [["Added", change.added], ["Removed", change.removed]].forEach(
    ([label, items]) => {
      const row = el("div", "drift-change");
      row.append(el("span", "drift-kind", label));
      if (!items.length) row.append(el("span", "muted", "None"));
      items.forEach((item) => row.append(el("span", "drift-label", item)));
      section.append(row);
    }
  );
  return section;
}

function signed(value, formatter) {
  if (value === null) return "not captured";
  if (value === 0) return formatter(0);
  return `${value > 0 ? "+" : "−"}${formatter(Math.abs(value))}`;
}

async function loadDrift() {
  const generation = ++driftGeneration;
  const leftSession = state.driftLeft;
  const rightSession = state.driftRight;
  const body = $("drift-body");
  body.replaceChildren();
  if (!leftSession || !rightSession) {
    body.append(el("p", "muted", "Two captured sessions are needed for comparison."));
    return;
  }
  if (leftSession === rightSession) {
    body.append(el("p", "note", "The same session is selected on both sides; no drift to compare."));
    return;
  }

  try {
    // The app has one SQLite connection. Keep these reads sequential so a
    // comparison that includes the selected session cannot overlap the main
    // summary's overview query on that connection.
    const leftProfile = await getJSON("/api/profile", { session_id: leftSession });
    if (generation !== driftGeneration) return;
    const rightProfile = await getJSON("/api/profile", { session_id: rightSession });
    if (generation !== driftGeneration) return;
    const leftOverview = await getJSON("/api/overview", { session_id: leftSession });
    if (generation !== driftGeneration) return;
    const rightOverview = await getJSON("/api/overview", { session_id: rightSession });
    if (generation !== driftGeneration) return;
    const before = leftProfile.observed || {};
    const after = rightProfile.observed || {};
    if (!before.interaction_count || !after.interaction_count) {
      body.append(el("p", "note", "One or both selected sessions are empty; observed label and metric changes may be incomplete."));
    }

    const labels = el("div", "drift-grid");
    const incomplete = (dimension) =>
      (before.truncated_dimensions || []).includes(dimension) ||
      (after.truncated_dimensions || []).includes(dimension) ||
      (dimension === "tool_names" &&
        (before.tool_names_truncated || after.tool_names_truncated));
    labels.append(driftLabels("Hosts", changedValues(before.hosts, after.hosts), incomplete("hosts")));
    labels.append(driftLabels("Tools", changedValues(before.tool_names, after.tool_names), incomplete("tool_names")));
    labels.append(driftLabels("Models", changedValues(before.models, after.models), incomplete("models")));
    body.append(labels);

    const leftTotals = leftOverview.totals || {};
    const rightTotals = rightOverview.totals || {};
    const leftBytes = (leftTotals.request_bytes || 0) + (leftTotals.response_bytes || 0);
    const rightBytes = (rightTotals.request_bytes || 0) + (rightTotals.response_bytes || 0);
    const latencyDelta = typeof leftTotals.avg_latency_ms === "number" &&
      typeof rightTotals.avg_latency_ms === "number"
      ? rightTotals.avg_latency_ms - leftTotals.avg_latency_ms
      : null;
    const metrics = el("dl", "drift-metrics");
    [
      ["Error rate", signed((after.error_rate || 0) - (before.error_rate || 0),
        (value) => `${(value * 100).toFixed(1)} pp`)],
      ["Average latency", signed(latencyDelta, (value) => fmtMs(value))],
      ["Transferred bytes", signed(rightBytes - leftBytes, (value) => fmtBytes(value))],
    ].forEach(([label, value]) => {
      metrics.append(el("dt", null, label));
      metrics.append(el("dd", null, value));
    });
    body.append(metrics);
  } catch (error) {
    if (generation !== driftGeneration) return;
    body.append(el("p", "note", "Comparison data is unavailable for one or both sessions."));
    console.error(error);
  }
}

function renderHosts(hosts) {
  const body = $("hosts");
  body.replaceChildren();
  const max = hosts.reduce((m, h) => Math.max(m, h.count), 0) || 1;

  if (!hosts.length) {
    const tr = el("tr");
    const td = el("td", "muted", "No hosts recorded yet.");
    td.colSpan = 5;
    tr.append(td);
    body.append(tr);
    return;
  }

  hosts.forEach((h) => {
    const tr = el("tr");
    tr.append(el("td", "host-name", h.host));

    const calls = el("td", "num", fmtInt(h.count));
    tr.append(calls);

    const failed = el("td", "num");
    if (h.errors > 0) failed.append(el("span", "pill pill-fail", h.errors));
    else failed.append(el("span", "muted", "0"));
    tr.append(failed);

    tr.append(el("td", "num", fmtMs(h.avg_latency_ms)));

    const barCell = el("td");
    const track = el("div", "bar-track");
    const bar = el("div", "bar");
    bar.style.width = `${Math.max(2, (h.count / max) * 100)}%`;
    track.append(bar);
    barCell.append(track);
    tr.append(barCell);

    tr.addEventListener("click", () => {
      state.host = state.host === h.host ? null : h.host;
      state.offset = 0;
      refresh();
    });

    body.append(tr);
  });
}

/* --------------------------------------------------------------------- log */

async function loadLog() {
  const params = { ...filterParams(), limit: state.limit, offset: state.offset };
  const data = await getJSON("/api/interactions", params);
  state.total = data.total;

  const body = $("log");
  body.replaceChildren();

  const empty = $("log-empty");
  if (!data.items.length) {
    empty.hidden = false;
    empty.textContent = state.total === 0 && !anyFilterActive()
      ? "Nothing captured yet. Run `raildash load <capture.jsonl>`, or point RailMon's webhook at this server."
      : "No interactions match these filters.";
  } else {
    empty.hidden = true;
  }

  data.items.forEach((row) => {
    const tr = el("tr");
    if (row.status_code >= 400) tr.dataset.sev = "fail";
    else if (row.status_code === null || row.status_code === undefined) {
      tr.dataset.sev = "warn";
    }

    tr.append(el("td", "muted", fmtTime(row.timestamp)));
    tr.append(el("td", null, row.method || "—"));
    tr.append(el("td", "cell-host", row.host || "—"));
    tr.append(el("td", "cell-path", row.path || "—"));

    const status = el("td");
    status.append(statusPill(row.status_code));
    tr.append(status);

    tr.append(el("td", "num", fmtMs(row.latency_ms)));
    tr.append(el("td", "num", fmtBytes((row.request_size || 0) + (row.response_size || 0))));

    const flags = el("td");
    if (row.tool_calls > 0) {
      const f = el("span", "flag flag-tool", `${row.tool_calls} tool`);
      f.title = `${row.tool_calls} tool call(s) in this exchange`;
      flags.append(f);
    }
    if (row.has_ticket) {
      const f = el("span", "flag flag-ticket", "x-rail");
      f.title = "Carried an x-rail ticket (the value is never stored)";
      flags.append(f);
    }
    tr.append(flags);

    tr.addEventListener("click", () => openDetail(row.id));
    body.append(tr);
  });

  const from = state.total ? state.offset + 1 : 0;
  const to = Math.min(state.offset + state.limit, state.total);
  $("pager-text").textContent = `${fmtInt(from)}–${fmtInt(to)} of ${fmtInt(state.total)}`;
  $("prev").disabled = state.offset <= 0;
  $("next").disabled = to >= state.total;
}

function anyFilterActive() {
  const p = filterParams();
  return Boolean(p.host || p.method || p.status_class || p.q || p.errors_only);
}

function renderActiveFilter() {
  const bar = $("active-filter");
  if (state.host) {
    bar.hidden = false;
    $("active-filter-text").textContent = `host = ${state.host}`;
  } else {
    bar.hidden = true;
  }
}

/* ------------------------------------------------------------------ detail */

function headerTable(headers) {
  const pre = el("pre");
  if (!headers || typeof headers !== "object") {
    pre.textContent = "(none captured)";
    return pre;
  }
  const lines = Object.entries(headers).map(([k, v]) => `${k}: ${v}`);
  pre.textContent = lines.length ? lines.join("\n") : "(none captured)";
  return pre;
}

function bodyBlock(body) {
  const pre = el("pre");
  if (body === null || body === undefined || body === "") {
    pre.textContent = "(empty)";
  } else if (typeof body === "string") {
    pre.textContent = body;
  } else {
    pre.textContent = JSON.stringify(body, null, 2);
  }
  return pre;
}

async function openDetail(rowId) {
  const data = await getJSON(`/api/interactions/${rowId}`);
  const raw = data.raw || {};
  const req = raw.request || {};
  const res = raw.response || {};

  $("detail-eyebrow").textContent =
    `${data.method || "—"} · ${data.status_code ?? "no response"}`;
  $("detail-h").textContent = `${data.host || "unknown host"}${data.path || ""}`;

  const body = $("detail-body");
  body.replaceChildren();

  const nav = data.navigation || {};
  [
    ["previous-error", nav.previous_error],
    ["next-error", nav.next_error],
    ["previous-tool", nav.previous_tool_call],
    ["next-tool", nav.next_tool_call],
  ].forEach(([id, target]) => {
    const button = $(id);
    button.disabled = !target;
    button.onclick = target ? () => openDetail(target) : null;
  });

  if (data.tool_names && data.tool_names.length) {
    const tools = el("section", "investigation-tools");
    tools.append(el("h3", null, "Captured tool names"));
    data.tool_names.forEach((name) => {
      tools.append(el("span", "tool-name", name));
    });
    body.append(tools);
  }

  const sequence = el("section", "nearby");
  sequence.append(el("h3", null, "Nearby on the same pid / tid"));
  const sequenceList = el("ol", "nearby-list");
  (data.nearby || []).forEach((row) => {
    const item = el("li");
    const button = el("button", "nearby-interaction");
    button.type = "button";
    button.dataset.current = String(row.id === data.id);
    button.append(el("span", "nearby-time", fmtTime(row.timestamp)));
    button.append(el("span", "nearby-target", `${row.method || "—"} ${row.host || "—"}${row.path || ""}`));
    button.append(statusPill(row.status_code));
    (row.tool_names || []).forEach((name) => {
      button.append(el("span", "tool-name", name));
    });
    button.addEventListener("click", () => openDetail(row.id));
    item.append(button);
    sequenceList.append(item);
  });
  sequence.append(sequenceList);
  sequence.id = "nearby-interactions";
  body.append(sequence);

  // Facts
  const dl = el("dl", "kv");
  const pairs = [
    ["When", data.timestamp || "—"],
    ["Latency", fmtMs(data.latency_ms)],
    ["Request", fmtBytes(data.request_size)],
    ["Response", fmtBytes(data.response_size)],
    ["Model", data.model || "—"],
    ["Tool calls", data.tool_calls || 0],
    ["Process", `pid ${data.pid ?? "—"} · tid ${data.tid ?? "—"}`],
    ["x-rail", data.has_ticket ? "present" : "absent"],
    ["Interaction id", data.interaction_id || "—"],
  ];
  pairs.forEach(([k, v]) => {
    dl.append(el("dt", null, k));
    dl.append(el("dd", null, v));
  });
  body.append(dl);

  if (!raw.request) {
    body.append(el("p", "note",
      "No request was paired with this response. That is normal for a " +
      "connection already open when the probe attached — the HTTP/2 HEADERS " +
      "frame carrying the method and path was never seen."));
  }

  const reqBlock = el("div", "block");
  reqBlock.dataset.dir = "out";
  reqBlock.append(el("h3", null, "Request headers"));
  reqBlock.append(headerTable(req.headers));
  reqBlock.append(el("h3", null, "Request body"));
  reqBlock.append(bodyBlock(req.body));
  body.append(reqBlock);

  const resBlock = el("div", "block");
  resBlock.dataset.dir = "in";
  resBlock.append(el("h3", null, "Response headers"));
  resBlock.append(headerTable(res.headers));
  resBlock.append(el("h3", null, "Response body"));
  resBlock.append(bodyBlock(res.body));
  body.append(resBlock);

  body.append(el("p", "note",
    "RailMon strips Authorization before anything leaves its process, so it " +
    "is absent here rather than hidden. Everything else is shown as captured."));

  $("detail").hidden = false;
  $("scrim").hidden = false;
  $("detail").focus();
}

function closeDetail() {
  $("detail").hidden = true;
  $("scrim").hidden = true;
}

/* ------------------------------------------------------------------- wiring */

let refreshing = false;
let driftGeneration = 0;

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    await loadSessions();
    renderActiveFilter();
    await Promise.all([loadOverview(), loadProfile(), loadLog()]);
    await loadDrift();
    await loadFilterOptions();
    setConn("live", staticDemo ? "fixture" : "live");
  } catch (err) {
    // Say what broke. A dashboard that silently shows stale numbers during an
    // incident is worse than one that admits it lost the server.
    setConn("down", "disconnected");
    console.error(err);
  } finally {
    refreshing = false;
  }
}

let filtersLoadedFor = null;

async function loadFilterOptions() {
  if (filtersLoadedFor === state.sessionId) return;
  const data = await getJSON("/api/filters", { session_id: state.sessionId });
  const select = $("f-method");
  const current = select.value;
  select.replaceChildren(el("option", null, "any method"));
  select.firstChild.value = "";
  data.methods.forEach((m) => {
    const opt = el("option", null, m);
    opt.value = m;
    select.append(opt);
  });
  select.value = data.methods.includes(current) ? current : "";
  filtersLoadedFor = state.sessionId;
}

function debounce(fn, ms) {
  let handle;
  return (...args) => {
    clearTimeout(handle);
    handle = setTimeout(() => fn(...args), ms);
  };
}

function initTheme() {
  const stored = localStorage.getItem("raildash-theme");
  if (stored === "dark" || stored === "light") {
    document.documentElement.dataset.theme = stored;
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
  $("theme").addEventListener("click", () => {
    const now = document.documentElement.dataset.theme;
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const effective = now || (prefersDark ? "dark" : "light");
    const next = effective === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("raildash-theme", next);
  });
}

function init() {
  initTheme();

  if (staticDemo) {
    $("demo-banner").hidden = false;
    setConn("live", "fixture");
  }

  $("refresh").addEventListener("click", refresh);
  $("drift-left").addEventListener("change", (event) => {
    state.driftLeft = event.target.value;
    loadDrift();
  });
  $("drift-right").addEventListener("change", (event) => {
    state.driftRight = event.target.value;
    loadDrift();
  });

  const rerun = () => {
    state.offset = 0;
    loadLog().catch((e) => console.error(e));
  };
  $("f-q").addEventListener("input", debounce(rerun, 220));
  $("f-method").addEventListener("change", rerun);
  $("f-status").addEventListener("change", rerun);
  $("f-errors").addEventListener("change", rerun);

  $("f-clear").addEventListener("click", () => {
    $("f-q").value = "";
    $("f-method").value = "";
    $("f-status").value = "";
    $("f-errors").checked = false;
    state.host = null;
    state.offset = 0;
    refresh();
  });

  $("active-filter-clear").addEventListener("click", () => {
    state.host = null;
    state.offset = 0;
    refresh();
  });

  $("prev").addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - state.limit);
    loadLog().catch((e) => console.error(e));
  });
  $("next").addEventListener("click", () => {
    state.offset += state.limit;
    loadLog().catch((e) => console.error(e));
  });

  $("detail-close").addEventListener("click", closeDetail);
  $("scrim").addEventListener("click", closeDetail);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDetail();
  });

  refresh();
  // A capture arriving over the webhook should show up without a reload; five
  // seconds is frequent enough to feel live and rare enough to stay quiet.
  if (!staticDemo) {
    setInterval(() => {
      if (document.visibilityState === "visible" && $("detail").hidden) refresh();
    }, 5000);
  }
}

document.addEventListener("DOMContentLoaded", init);
