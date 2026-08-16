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
};

const $ = (id) => document.getElementById(id);

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

function fmtMs(ms) {
  if (typeof ms !== "number" || Number.isNaN(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)} s`;
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
  $("stat-latency").textContent =
    `${fmtMs(t.avg_latency_ms)} / ${fmtMs(t.max_latency_ms)}`;

  const total = (t.request_bytes || 0) + (t.response_bytes || 0);
  $("stat-bytes").textContent = fmtBytes(total);
  $("stat-bytes-note").textContent =
    `${fmtBytes(t.request_bytes || 0)} out · ${fmtBytes(t.response_bytes || 0)} in`;

  renderHosts(data.hosts || []);
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

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    await loadSessions();
    renderActiveFilter();
    await Promise.all([loadOverview(), loadLog()]);
    await loadFilterOptions();
    setConn("live", "live");
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

  $("refresh").addEventListener("click", refresh);

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
  setInterval(() => {
    if (document.visibilityState === "visible" && $("detail").hidden) refresh();
  }, 5000);
}

document.addEventListener("DOMContentLoaded", init);
