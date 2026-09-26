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
  aspDriftOffsets: {},
};

const $ = (id) => document.getElementById(id);
const staticDemo = window.RAIL_DASH_STATIC_DEMO === true;
let staticDataPromise = null;

// DR-120: the per-start local write token RailDash injects into the page it
// serves (see app.py's `index()`/`require_local_token`). Every write route,
// plus the two reads that carry exact evidence (bundle/drift-explained),
// check this header; a cross-site page cannot read it because it cannot read
// this page's own DOM.
const LOCAL_TOKEN = (() => {
  const meta = document.querySelector('meta[name="raildash-token"]');
  return meta ? meta.content : "";
})();

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

// Same as getJSON, but for the two token-gated reads that carry exact
// evidence (ASP bundle inspect, drift-explained) rather than redacted
// summaries.
async function getJSONWithToken(path, params) {
  const url = new URL(path, window.location.origin);
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== "" && v !== false) {
      url.searchParams.set(k, v);
    }
  });
  const res = await fetch(url, {
    headers: { Accept: "application/json", "X-RailDash-Token": LOCAL_TOKEN },
  });
  if (!res.ok) throw await _apiError(res);
  return res.json();
}

async function _apiError(res) {
  let detail = `${res.status} ${res.statusText}`;
  try {
    const body = await res.json();
    if (body && typeof body.detail === "string") detail = body.detail;
  } catch (e) {
    /* body was not JSON; keep the status text */
  }
  return new Error(detail);
}

async function postJSON(path, body, params) {
  const url = new URL(path, window.location.origin);
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== "") url.searchParams.set(k, v);
  });
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-RailDash-Token": LOCAL_TOKEN },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) throw await _apiError(res);
  return res.status === 204 ? null : res.json();
}

async function postRawBody(path, rawBytes, params) {
  const url = new URL(path, window.location.origin);
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== null && v !== undefined && v !== "") url.searchParams.set(k, v);
  });
  const res = await fetch(url, {
    method: "POST",
    headers: { "X-RailDash-Token": LOCAL_TOKEN },
    body: rawBytes,
  });
  if (!res.ok) throw await _apiError(res);
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

/* ----------------------------------------------------------- ASP alignment */

const ASP_DRIFT_PAGE_SIZE = 20;
let lastAspAnnouncement = null;

function identityLabel(identity) {
  const value = identity && identity.value;
  if (!identity) return "Unknown agent";
  if (identity.kind === "deployment_environment") {
    return `${value.deployment} / ${value.namespace}`;
  }
  if (identity.kind === "deployment_compose") {
    return `${value.project} / ${value.service} @ ${value.host_id}`;
  }
  return String(value);
}

function aspCommand(command) {
  const block = el("code", "asp-command", command);
  block.tabIndex = 0;
  return block;
}

function statePresentation(name) {
  const states = {
    NO_ACTIVE_ALIGNMENT: ["No active alignment", "neutral"],
    ALIGNMENT_ACTIVE: ["Alignment active", "neutral"],
    ALIGNED: ["Aligned", "ok"],
    DRIFT_DETECTED: ["Drift detected", "fail"],
    COMPARISON_UNAVAILABLE: ["Comparison unavailable", "warn"],
  };
  return states[name] || ["Comparison unavailable", "warn"];
}

function renderDriftGroups(result) {
  const wrapper = el("div", "asp-drift-groups");
  const groups = new Map();
  (result.changes || []).forEach((change) => {
    const kind = change.type.split("_")[0].toLowerCase();
    if (!groups.has(kind)) groups.set(kind, []);
    groups.get(kind).push(change);
  });
  groups.forEach((changes, kind) => {
    const group = el("section", "asp-drift-group");
    group.append(el("h4", null, kind));
    const list = el("ul");
    changes.forEach((change) => {
      const item = el("li");
      item.append(el("span", "asp-change-name", change.name));
      item.append(el("span", "asp-change-type", change.type));
      if ((change.fields || []).length) {
        item.append(el("span", "asp-change-fields", change.fields.join(", ")));
      }
      list.append(item);
    });
    group.append(list);
    wrapper.append(group);
  });
  return wrapper;
}

// DR-120: every one of these calls a write route wrapping the same
// Store/asp.py function the CLI subcommand named beside it calls. Each write
// action carries the local token (postJSON/postRawBody, above) and, on
// success, forces a rebuild of this identity's card (loadAspAlignments with a
// non-null focusKey bypasses the keyboard-focus poll guard the same way the
// existing drift pager buttons already do below).

function setInlineStatus(node, message, tone) {
  node.textContent = message || "";
  if (tone) node.dataset.tone = tone;
  else delete node.dataset.tone;
}

function suggestNextVersion(existingVersions) {
  return `v${(existingVersions || []).length + 1}.0`;
}

async function fetchAllPages(path, extraParams) {
  const items = [];
  let offset = 0;
  let total = 0;
  do {
    const page = await getJSON(path, { ...(extraParams || {}), limit: 500, offset });
    items.push(...page.items);
    total = page.total;
    if (!page.items.length) break;
    offset += page.items.length;
  } while (offset < total);
  return items;
}

function renderLockForm({ suggestedVersion, buttonLabel, onLock }) {
  const form = el("div", "asp-inline-form");
  const input = el("input");
  input.type = "text";
  input.value = suggestedVersion;
  input.setAttribute("aria-label", "Alignment version label");
  const button = el("button", "btn", buttonLabel || "Lock as baseline");
  button.type = "button";
  const status = el("span", "asp-status-msg");
  status.setAttribute("aria-live", "polite");
  button.addEventListener("click", async () => {
    const version = input.value.trim();
    if (!version) {
      setInlineStatus(status, "A version label is required.", "err");
      return;
    }
    button.disabled = true;
    setInlineStatus(status, "Working…");
    try {
      await onLock(version);
      setInlineStatus(status, "Done.", "ok");
    } catch (error) {
      setInlineStatus(status, error.message, "err");
    } finally {
      button.disabled = false;
    }
  });
  form.append(input, button, status);
  return form;
}

function renderVersionPicker(versions, activeId, onSwitch) {
  const wrap = el("div", "asp-version-picker");
  if (!versions.length) {
    wrap.append(el("span", "muted", "No alignment version locked yet."));
    return wrap;
  }
  const select = el("select");
  select.setAttribute("aria-label", "Alignment version");
  versions.forEach((version) => {
    const opt = el("option", null, `${version.version}${version.active ? " (active)" : ""}`);
    opt.value = version.alignment_version_id;
    if (version.alignment_version_id === activeId) opt.selected = true;
    select.append(opt);
  });
  const button = el("button", "btn btn-quiet", "Switch");
  button.type = "button";
  const status = el("span", "asp-status-msg");
  status.setAttribute("aria-live", "polite");
  button.addEventListener("click", async () => {
    button.disabled = true;
    setInlineStatus(status, "Switching…");
    try {
      await onSwitch(select.value);
      setInlineStatus(status, "Switched.", "ok");
    } catch (error) {
      setInlineStatus(status, error.message, "err");
    } finally {
      button.disabled = false;
    }
  });
  wrap.append(select, button, status);
  return wrap;
}

function describeEvidenceRecord(record) {
  if (!record) return "(absent)";
  if (record && typeof record === "object" && "value" in record) {
    const qualifiers = [record.status, record.tier].filter(Boolean).join(", ");
    return `${JSON.stringify(record.value)}${qualifiers ? ` [${qualifiers}]` : ""}`;
  }
  return JSON.stringify(record);
}

function renderDiffRow(change) {
  const row = el("div", "asp-diff-row");
  row.append(el("span", "asp-change-name", `${change.type} · ${change.name}`));
  const dl = el("dl");
  dl.append(el("dt", null, "Before"));
  dl.append(el("dd", "asp-diff-old", describeEvidenceRecord(change.baseline)));
  dl.append(el("dt", null, "After"));
  dl.append(el("dd", "asp-diff-new", describeEvidenceRecord(change.current)));
  if ((change.fields || []).length) {
    dl.append(el("dt", null, "Fields changed"));
    dl.append(el("dd", null, change.fields.join(", ")));
  }
  row.append(dl);
  return row;
}

async function renderDriftExplained(aspId) {
  const wrapper = el("div", "asp-diff-table");
  try {
    const explained = await getJSONWithToken(
      `/api/asps/${encodeURIComponent(aspId)}/drift/explained`,
      { limit: ASP_DRIFT_PAGE_SIZE }
    );
    (explained.changes || []).forEach((change) => wrapper.append(renderDiffRow(change)));
    if (!(explained.changes || []).length) {
      wrapper.append(el("p", "muted", "No per-attribute detail available for this page."));
    }
  } catch (error) {
    const msg = el("p", "asp-status-msg", `Could not load per-attribute detail: ${error.message}`);
    msg.dataset.tone = "err";
    wrapper.append(msg);
  }
  return wrapper;
}

function renderInspectToggle(aspId) {
  const wrap = el("div");
  const button = el("button", "btn btn-quiet", "Inspect evidence");
  button.type = "button";
  let view = null;
  button.addEventListener("click", async () => {
    if (view) {
      view.remove();
      view = null;
      button.textContent = "Inspect evidence";
      return;
    }
    button.disabled = true;
    try {
      const bundle = await getJSONWithToken(`/api/asps/${encodeURIComponent(aspId)}/bundle`);
      view = el("div", "asp-bundle-view");
      view.append(el("pre", null, JSON.stringify(bundle, null, 2)));
      wrap.append(view);
      button.textContent = "Hide evidence";
    } catch (error) {
      const msg = el("p", "asp-status-msg", error.message);
      msg.dataset.tone = "err";
      wrap.append(msg);
    } finally {
      button.disabled = false;
    }
  });
  wrap.append(button);
  return wrap;
}

async function loadAspAlignments(focusKey = null, focusAction = null) {
  const body = $("asp-alignment-body");
  // Polling must not destroy a keyboard user's focused command or pager.
  // Explicit pager navigation, and a write action's own refresh, supply a
  // focusKey and are allowed to rebuild.
  if (focusKey === null && body.contains(document.activeElement)) return;
  body.replaceChildren();
  if (staticDemo) {
    body.append(el("p", "muted", "ASP alignment is available in the live local dashboard."));
    return;
  }

  const asps = await fetchAllPages("/api/asps");
  if (!asps.length) {
    const empty = el("section", "asp-empty");
    empty.append(el("h3", null, "No ASP loaded"));
    empty.append(el("p", "muted", "Drop a validated RailMon evidence bundle on the box above, or:"));
    empty.append(aspCommand("raildash asp load evidence-bundle.json"));
    body.append(empty);
    return;
  }

  const allVersions = await fetchAllPages("/api/alignments");
  const versionsByIdentity = new Map();
  allVersions.forEach((version) => {
    const key = JSON.stringify(version.agent_identity);
    if (!versionsByIdentity.has(key)) versionsByIdentity.set(key, []);
    versionsByIdentity.get(key).push(version);
  });

  const latest = new Map();
  asps.forEach((asp) => {
    const key = JSON.stringify(asp.agent_identity);
    if (!latest.has(key)) latest.set(key, asp);
  });

  const states = await Promise.all([...latest.entries()].map(async ([key, asp]) => {
    const alignment = await getJSON(`/api/asps/${encodeURIComponent(asp.asp_id)}/state`);
    let drift = null;
    if (alignment.drift) {
      const offset = state.aspDriftOffsets[key] || 0;
      drift = await getJSON(`/api/asps/${encodeURIComponent(asp.asp_id)}/drift`, {
        limit: ASP_DRIFT_PAGE_SIZE,
        offset,
      });
      if (!drift.changes.length && drift.available_change_count > 0 && offset > 0) {
        const lastOffset = Math.floor(
          (drift.available_change_count - 1) / ASP_DRIFT_PAGE_SIZE
        ) * ASP_DRIFT_PAGE_SIZE;
        state.aspDriftOffsets[key] = lastOffset;
        drift = await getJSON(`/api/asps/${encodeURIComponent(asp.asp_id)}/drift`, {
          limit: ASP_DRIFT_PAGE_SIZE,
          offset: lastOffset,
        });
      }
    }
    return { key, asp, alignment, drift };
  }));

  let focusTarget = null;
  for (const { key, asp, alignment, drift } of states) {
    const card = el("article", "asp-state-card");
    const head = el("div", "asp-state-head");
    const title = el("div");
    title.append(el("h3", null, identityLabel(alignment.asp.agent_identity)));
    title.append(el("span", "asp-subject",
      `${alignment.asp.subject.host_id} / ${alignment.asp.subject.sandbox_name}`));
    const [label, tone] = statePresentation(alignment.state);
    const status = el("span", `asp-state asp-state-${tone}`, label);
    head.append(title, status);
    card.append(head);

    const versions = versionsByIdentity.get(key) || [];
    const activeVersion = versions.find((v) => v.active);
    const refresh = () => loadAspAlignments(key, "action");
    const doLock = async (version) => {
      await postJSON(`/api/asps/${encodeURIComponent(asp.asp_id)}/lock`, { version });
      refresh();
    };
    const doLockAndActivate = async (version) => {
      const locked = await postJSON(`/api/asps/${encodeURIComponent(asp.asp_id)}/lock`, { version });
      await postJSON(
        `/api/alignments/${encodeURIComponent(locked.alignment_version_id)}/switch`, {}
      );
      refresh();
    };
    const doSwitch = async (alignmentVersionId) => {
      await postJSON(`/api/alignments/${encodeURIComponent(alignmentVersionId)}/switch`, {});
      refresh();
    };
    const doAccept = async (version) => {
      await postJSON(`/api/asps/${encodeURIComponent(asp.asp_id)}/accept-drift`, { version });
      refresh();
    };

    if (alignment.state === "NO_ACTIVE_ALIGNMENT" && versions.length === 0) {
      // The first ASP ever loaded for this identity: auto-offer locking it as
      // the alignment baseline in one click (standing decision: every ASP
      // workflow -- including this one -- works from the UI, not just the CLI).
      const banner = el("section", "asp-banner");
      banner.append(el("h4", null, "Lock this as your alignment baseline?"));
      banner.append(el("p", "muted",
        "This is the first Agent Security Profile loaded for this agent identity. " +
        "Locking it activates it immediately as the version everything else is compared against."));
      banner.append(renderLockForm({
        suggestedVersion: "v1.0",
        buttonLabel: "Lock this as your alignment baseline",
        onLock: doLockAndActivate,
      }));
      banner.append(aspCommand(
        `raildash asp lock ${alignment.asp.asp_id} --version v1.0 && raildash asp switch <returned-id>`
      ));
      card.append(banner);
    } else if (alignment.state === "NO_ACTIVE_ALIGNMENT") {
      card.append(el("p", "muted", "No alignment version is active yet for this agent identity."));
      card.append(renderVersionPicker(versions, null, doSwitch));
      card.append(renderLockForm({
        suggestedVersion: suggestNextVersion(versions),
        buttonLabel: "Lock this ASP as a new version",
        onLock: doLock,
      }));
      card.append(aspCommand("raildash asp switch aspver-..."));
    } else if (alignment.state === "COMPARISON_UNAVAILABLE") {
      card.append(el("p", "asp-reason", `Reason: ${alignment.drift.reason}`));
      card.append(el("p", "muted",
        "This ASP cannot be compared with the active alignment. Lock it as a new version, then switch to it."));
      card.append(renderVersionPicker(
        versions, activeVersion ? activeVersion.alignment_version_id : null, doSwitch
      ));
      card.append(renderLockForm({
        suggestedVersion: suggestNextVersion(versions),
        buttonLabel: "Lock as new baseline",
        onLock: doLock,
      }));
      card.append(aspCommand(`raildash asp lock ${alignment.asp.asp_id} --version ${suggestNextVersion(versions)}`));
      card.append(aspCommand("raildash asp switch aspver-..."));
    } else if (alignment.state === "ALIGNMENT_ACTIVE") {
      card.append(el("p", "muted", "Load a later ASP for this agent to run the first comparison."));
      card.append(renderVersionPicker(
        versions, activeVersion ? activeVersion.alignment_version_id : null, doSwitch
      ));
      card.append(aspCommand("raildash asp load evidence-bundle.json"));
    } else if (alignment.state === "ALIGNED") {
      card.append(renderVersionPicker(
        versions, activeVersion ? activeVersion.alignment_version_id : null, doSwitch
      ));
    }

    if (alignment.state === "DRIFT_DETECTED") {
      card.append(renderVersionPicker(
        versions, activeVersion ? activeVersion.alignment_version_id : null, doSwitch
      ));
      const acceptWrap = el("div", "asp-actions");
      acceptWrap.append(renderLockForm({
        suggestedVersion: suggestNextVersion(versions),
        buttonLabel: "Accept new state as new baseline",
        onLock: doAccept,
      }));
      card.append(acceptWrap);
      card.append(aspCommand(`raildash asp lock ${alignment.asp.asp_id} --version ${suggestNextVersion(versions)}`));
      card.append(aspCommand("raildash asp switch aspver-..."));
    }

    card.append(renderInspectToggle(asp.asp_id));

    if (drift && drift.change_count > 0) {
      card.append(renderDriftGroups(drift));
      if (alignment.state === "DRIFT_DETECTED") {
        card.append(await renderDriftExplained(asp.asp_id));
      }
      const offset = drift.offset || 0;
      const pager = el("div", "asp-drift-pager");
      const previous = el("button", "btn btn-quiet", "Previous changes");
      previous.type = "button";
      previous.disabled = offset === 0;
      previous.addEventListener("click", () => {
        state.aspDriftOffsets[key] = Math.max(0, offset - ASP_DRIFT_PAGE_SIZE);
        loadAspAlignments(key, "previous").catch((error) => console.error(error));
      });
      const next = el("button", "btn btn-quiet", "Next changes");
      next.type = "button";
      next.disabled = offset + drift.changes.length >= drift.available_change_count;
      next.addEventListener("click", () => {
        state.aspDriftOffsets[key] = offset + ASP_DRIFT_PAGE_SIZE;
        loadAspAlignments(key, "next").catch((error) => console.error(error));
      });
      const availableLabel = drift.available_change_count === drift.change_count
        ? `${drift.change_count}`
        : `${drift.available_change_count} retained · ${drift.change_count} detected`;
      pager.append(previous,
        el("span", "pager-text", `${offset + 1}–${offset + drift.changes.length} of ${availableLabel}`),
        next);
      card.append(pager);
      if (key === focusKey) {
        focusTarget = focusAction === "previous" ? previous : next;
        if (focusTarget.disabled) {
          focusTarget = focusAction === "previous" ? next : previous;
        }
      }
    }
    body.append(card);
  }
  const announcement = states
    .map(({ alignment }) => (
      `${identityLabel(alignment.asp.agent_identity)}: ${statePresentation(alignment.state)[0]}`
    ))
    .join("; ");
  if (announcement !== lastAspAnnouncement) {
    $("asp-status-announcement").textContent = announcement;
    lastAspAnnouncement = announcement;
  }
  if (focusTarget) focusTarget.focus();
}

function initAspUpload() {
  const zone = $("asp-upload");
  const input = $("asp-upload-input");
  const status = $("asp-upload-status");

  const ingest = async (file) => {
    setInlineStatus(status, `Loading ${file.name}…`);
    try {
      const raw = await file.arrayBuffer();
      const result = await postRawBody("/v1/evidence-bundles", raw);
      setInlineStatus(
        status,
        result.duplicate ? `Already stored as ${result.asp_id}.` : `Loaded as ${result.asp_id}.`,
        "ok"
      );
      loadAspAlignments("upload", "action").catch((error) => console.error(error));
    } catch (error) {
      setInlineStatus(status, error.message, "err");
    }
  };

  zone.addEventListener("dragover", (event) => {
    event.preventDefault();
    zone.classList.add("dragover");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    zone.classList.remove("dragover");
    const file = event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) ingest(file);
  });
  input.addEventListener("change", () => {
    const file = input.files && input.files[0];
    if (file) ingest(file);
    input.value = "";
  });
}

async function loadAspRetentionSettings() {
  const settings = await getJSON("/api/settings/asp-retention");
  $("asp-retention-keep").value = settings.keep_count;
  $("asp-retention-days").value = settings.max_age_days;
}

function initAspRetention() {
  const status = $("asp-retention-status");
  $("asp-retention-save").addEventListener("click", async () => {
    const keepCount = parseInt($("asp-retention-keep").value, 10);
    const maxAgeDays = parseInt($("asp-retention-days").value, 10);
    if (!Number.isInteger(keepCount) || keepCount < 1 || !Number.isInteger(maxAgeDays) || maxAgeDays < 1) {
      setInlineStatus(status, "Both values must be positive integers.", "err");
      return;
    }
    setInlineStatus(status, "Saving…");
    try {
      // The CLI equivalent of this control is `raildash asp retention-set`.
      await postJSON("/api/settings/asp-retention", {
        keep_count: keepCount,
        max_age_days: maxAgeDays,
      });
      setInlineStatus(status, "Saved.", "ok");
    } catch (error) {
      setInlineStatus(status, error.message, "err");
    }
  });
  $("asp-retention-prune").addEventListener("click", async () => {
    setInlineStatus(status, "Pruning…");
    try {
      const result = await postJSON("/api/asps/prune", {});
      setInlineStatus(status, `Pruned ${result.removed} unlocked ASP(s).`, "ok");
      loadAspAlignments("prune", "action").catch((error) => console.error(error));
    } catch (error) {
      setInlineStatus(status, error.message, "err");
    }
  });
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
    await Promise.all([loadOverview(), loadProfile(), loadLog(), loadAspAlignments()]);
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
    $("asp-upload").hidden = true;
    $("asp-retention").hidden = true;
    setConn("live", "fixture");
  } else {
    initAspUpload();
    initAspRetention();
    loadAspRetentionSettings().catch((error) => console.error(error));
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
