"use strict";

// The whole screen is the stepper: one step at a time, showing only what that
// step needs. Everything on screen is driven from one state snapshot, pushed over
// a websocket; polling is only the fallback for when the socket cannot be made.

const $ = (id) => document.getElementById(id);

let known = null;
let lastEventSeq = 0;
let socket = null;
let pollTimer = null;
let lastPush = 0;
let unseen = 0;
let logLines = [];

// which actions belong on which step. The VM starts by itself, so there is no
// start button anywhere; stopping it and taking the report away is the end of the
// flow and nothing else is offered. A step's buttons stay visible but disabled
// until their moment comes, so the next move is always obvious.
const STEP_ACTIONS = [
  [],
  ["send_to_vm", "scan_device"],
  [],
  ["stop_vm"],
];

function setText(id, value) {
  const el = $(id);
  if (el && el.textContent !== String(value)) el.textContent = value;
}

// -- where are we in the flow ------------------------------------------------

function stepFor(s) {
  const device = s.device;
  if (s.state === "scanning" || (s.scan && s.scan.running)) return 3;
  if (s.state === "results" && s.report) return 4;
  if (!device) return 1;
  return 2;
}

function renderStep(step) {
  document.querySelectorAll(".rail li").forEach((li) => {
    const n = Number(li.dataset.step);
    li.classList.toggle("done", n < step);
    li.classList.toggle("active", n === step);
  });
  document.querySelectorAll("[data-stage]").forEach((article) => {
    article.hidden = Number(article.dataset.stage) !== step;
  });
}

function renderRailNote(s) {
  const note = $("rail-note");
  note.textContent = s.state === "results"
    ? "Evidence is never mounted on the host. Hashes went to VirusTotal; file contents never left the guest."
    : "Evidence is never mounted on the host. The disk goes to the disposable guest read-only, hashing happens in the guest, and only hashes go to VirusTotal.";
}

// -- the header --------------------------------------------------------------

function renderHeader(s) {
  setText("state-pill", s.state);
  const vm = s.vm || {};
  setText("vm-status", vm.running ? (vm.ssh_ok ? "VM up, ssh ready" : "VM booting") : "VM stopped");
  $("vm-dot").className = "dot" + (vm.running ? (vm.ssh_ok ? " on" : " warn") : "");
  const d = s.device;
  setText("device-line", d
    ? `${d.devnode || "?"} · ${d.size_human || d.size || "?"} · ${[d.vendor, d.model].filter(Boolean).join(" ") || "unknown model"}${d.guest_node ? ` · in the VM as ${d.guest_node}` : ""}`
    : "no device yet");
}

// -- buttons -----------------------------------------------------------------

function renderActions(s, step) {
  const allowed = s.allowed_actions || [];
  const vm = s.vm || {};
  document.querySelectorAll("button[data-action]").forEach((btn) => {
    if (!STEP_ACTIONS[step - 1].includes(btn.dataset.action)) {
      btn.hidden = true;
      return;
    }
    btn.hidden = false;
    // visible but disabled until its moment: sending needs the guest's ssh up,
    // scanning needs the disk inside the guest
    let ready = allowed.includes(btn.dataset.action);
    if (btn.dataset.action === "send_to_vm") ready = ready && !!vm.ssh_ok;
    if (btn.dataset.action === "scan_device") {
      ready = ready && !!(s.device && s.device.guest_node);
    }
    btn.disabled = !ready;
  });
  $("btn-export").hidden = !s.report;
}

// -- step 2: what was plugged in ---------------------------------------------

function renderDevice(device, vm) {
  if (!device) return;
  vm = vm || {};
  setText("d-devnode", device.devnode || "-");
  setText("d-size", device.size_human || device.size || "-");
  setText("d-model", [device.vendor, device.model].filter(Boolean).join(" ") || "-");
  setText("d-serial", device.serial || "-");
  setText("d-bus", device.bus || "-");
  setText("d-fstype", device.fstype || "read in the guest");
  setText("d-label", device.label || "-");
  setText("a-devnode", device.devnode || "-");
  setText("a-hostnode", device.devnode || "-");
  setText("a-guest", device.guest_node ? `${device.guest_node} (read-only)` : "not attached yet");
  setText("d-vmstatus", !vm.running ? "starting…" : (vm.ssh_ok ? "ready" : "booting…"));
}

// -- the arrival alert ---------------------------------------------------------

let hadDevice = false;

function renderToast(s) {
  const toast = $("toast");
  if (s.device && !hadDevice) {
    // the found-step is gone, so an arrival announces itself instead
    hadDevice = true;
    const d = s.device;
    setText("toast-text",
      `storage found: ${d.devnode || "a device"} · ${d.size_human || d.size || ""}`);
    toast.hidden = false;
    clearTimeout(renderToast.timer);
    renderToast.timer = setTimeout(() => { toast.hidden = true; }, 10000);
  } else if (!s.device) {
    hadDevice = false;
    toast.hidden = true;
  }
}

// -- step 3: the scan, as one live status --------------------------------------

function renderScan(scan, state) {
  // this step only ever shows while a scan is running; otherwise there is
  // nothing to say here
  if (!scan || (!scan.running && state !== "scanning")) return;
  const checking = (scan.vt_total || 0) > 0;
  setText("scan-phase", checking
    ? "checking file hashes on VirusTotal"
    : `walking ${scan.node || "the disk"} inside the guest`);
  const counts = [`${(scan.entries || 0).toLocaleString()} records walked`];
  if (checking) {
    counts.push(`${(scan.vt_done || 0).toLocaleString()} of ${scan.vt_total.toLocaleString()} hashes checked`);
  }
  if (scan.vt_flagged) counts.push(`${scan.vt_flagged} flagged`);
  setText("scan-counts", counts.join("  ·  "));
  const bar = $("vt-bar");
  if (checking && scan.vt_total) {
    bar.classList.remove("crawl");
    bar.style.width = `${Math.min(100, (scan.vt_done / scan.vt_total) * 100)}%`;
    setText("scan-detail", "hashes only — no file content leaves this machine");
  } else {
    // walking has no total, so the bar crawls instead of pretending a percent
    bar.classList.add("crawl");
    bar.style.width = "30%";
    setText("scan-detail", "hashing files inside the guest");
  }
}

// -- step 6: the report ------------------------------------------------------

const TABLE_ROWS = 200;         // the table is a sample; the export has everything

function renderReport(report, device) {
  const summary = $("report-summary");
  const meta = $("report-meta");
  const listing = $("listing-block");
  const flaggedBlock = $("flagged-block");
  summary.hidden = !report;
  meta.hidden = !report;
  listing.hidden = !report;
  flaggedBlock.hidden = true;
  $("report-rows").textContent = "";
  $("flagged-list").textContent = "";

  const line = $("verdict");
  if (device) {
    setText("sheet-device",
      [device.devnode, device.size_human || device.size,
       [device.vendor, device.model].filter(Boolean).join(" "),
       device.label ? `"${device.label}"` : ""].filter(Boolean).join("  ·  "));
  }
  if (!report) {
    line.className = "sheet-line";
    line.textContent = "nothing scanned yet";
    $("sheet-verdict").className = "sheet-verdict";
    setText("r-malicious", "0");
    return;
  }

  const s = report.summary || {};
  const rows = report.rows || [];
  const flagged = rows.filter((row) => row.virustotal === "malicious");
  const clean = rows.filter((row) => row.virustotal === "clean");
  const unknown = rows.length - flagged.length - clean.length;

  // one line that answers the only question: is this disk bad
  line.className = "sheet-line " + (flagged.length ? "bad" : (unknown ? "warn" : "good"));
  line.textContent = flagged.length
    ? (flagged.length === 1 ? "1 file flagged as malicious"
                            : `${flagged.length} files flagged as malicious`)
    : (unknown ? `nothing flagged · ${unknown} hashes never seen by VirusTotal`
               : `nothing flagged in ${rows.length} files`);
  $("sheet-verdict").className = "sheet-verdict "
    + (flagged.length ? "bad" : (unknown ? "warn" : "good"));
  setText("r-malicious", flagged.length.toLocaleString());
  setText("r-files", (s.files || rows.length).toLocaleString());
  setText("r-clean", clean.length.toLocaleString());
  setText("r-unknown", unknown.toLocaleString());
  setText("r-seconds", s.seconds || 0);

  if (flagged.length) {
    flagged.forEach((row) => {
      const li = document.createElement("li");
      const path = document.createElement("span");
      path.className = "fpath";
      path.textContent = row.path || "-";
      const detail = document.createElement("span");
      detail.className = "fdetail";
      const engines = (row.engines || []).slice(0, 3)
        .map((e) => `${e.engine}: ${e.result}`).join(", ");
      detail.textContent = `${row.detections || 0}/${row.scanned || 0} engines`
        + (engines ? ` · ${engines}` : "");
      li.append(path, detail);
      $("flagged-list").appendChild(li);
    });
    flaggedBlock.hidden = false;
  }

  renderFileTable(rows);
  const shown = Math.min(rows.length, TABLE_ROWS);
  setText("listing-note", rows.length > TABLE_ROWS
    ? `showing ${shown} of ${rows.length.toLocaleString()} files · the export has all of them`
    : `${rows.length.toLocaleString()} files, all checked`);
  setText("report-meta",
    [`${(s.entries || 0).toLocaleString()} entries walked`,
     `${(s.hashed || 0).toLocaleString()} hashed in the guest`,
     `${(s.hidden || 0) + (s.hidden_dot || 0)} hidden`,
     `${s.unhashed || 0} unhashed`, `${s.errors || 0} errors`].join("  ·  "));
}

function renderFileTable(rows) {
  const tbody = $("report-rows");
  tbody.textContent = "";
  const ordered = [...rows].sort((a, b) => {
    const rank = (row) => (row.virustotal === "malicious" ? 0 : 1);
    return rank(a) - rank(b) || (b.size || 0) - (a.size || 0);
  });
  ordered.slice(0, TABLE_ROWS).forEach((row) => {
    const name = row.virustotal || "not checked";
    const tr = document.createElement("tr");
    if (name === "malicious") tr.className = "flagged";
    const badge = document.createElement("td");
    badge.className = "v-" + name.replace(/[^a-z]/g, "");
    badge.textContent = name;
    const detections = document.createElement("td");
    detections.textContent = row.scanned ? `${row.detections || 0}/${row.scanned}` : "-";
    const size = document.createElement("td");
    size.textContent = row.size !== undefined ? row.size : "-";
    const hidden = document.createElement("td");
    hidden.textContent = row.hidden ? "attr" : (row.hidden_dot ? "dot" : "");
    const path = document.createElement("td");
    path.className = "name";
    path.textContent = row.path || "-";
    const hash = document.createElement("td");
    hash.textContent = (row.sha256 || "").slice(0, 16) || "-";
    const engine = document.createElement("td");
    engine.textContent = row.vt_error || (name === "malicious" && row.vt_name
      ? row.vt_name : name);
    tr.append(badge, detections, size, hidden, path, hash, engine);
    tbody.appendChild(tr);
  });
  $("report-table-wrap").hidden = rows.length === 0;
  const toggle = $("btn-toggle-files");
  toggle.hidden = rows.length === 0;
  toggle.textContent = "hide";
}

$("btn-toggle-files").addEventListener("click", () => {
  const wrap = $("report-table-wrap");
  wrap.hidden = !wrap.hidden;
  $("btn-toggle-files").textContent = wrap.hidden ? "show" : "hide";
});

// -- the export --------------------------------------------------------------

async function exportReport() {
  const btn = $("btn-export");
  btn.disabled = true;
  try {
    const response = await fetch("/api/report.pdf", {
      headers: { "X-Triage-Token": window.TRIAGE_TOKEN },
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      showError(payload.error || `export failed: HTTP ${response.status}`);
      return;
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = (response.headers.get("Content-Disposition") || "")
      .match(/filename="([^"]+)"/)?.[1] || "airlock-report.pdf";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showError("");
  } catch (err) {
    showError(`export failed: ${err}`);
  } finally {
    btn.disabled = false;
  }
}

$("btn-export").addEventListener("click", exportReport);

// -- the arrival alert -------------------------------------------------------

$("toast-go").addEventListener("click", () => { $("toast").hidden = true; });
$("toast-x").addEventListener("click", () => { $("toast").hidden = true; });

// -- the event log, behind a button ------------------------------------------

function logText() {
  return logLines.length ? logLines : (known && known.events ? known.events : []);
}

function appendLog(event) {
  if (event.seq <= lastEventSeq) return;
  lastEventSeq = event.seq;
  logLines.push(event);
  const pre = $("log");
  const stick = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 24;
  pre.textContent += `${event.time}  ${event.text}\n`;
  if (stick) pre.scrollTop = pre.scrollHeight;
  const dialog = $("log-dialog");
  if (!dialog.open && (unseen += 1) >= 1) $("log-badge").hidden = false;
  if (event.level === "error") {
    $("btn-log").classList.add("alert");
    if (!dialog.open) $("log-badge").hidden = false;
  }
}

function fillLog(events) {
  logLines = logLines.length ? logLines : events.slice();
  $("log").textContent = logLines.map((e) => `${e.time}  ${e.text}`).join("\n")
    + (logLines.length ? "\n" : "");
  if (logLines.length) lastEventSeq = logLines[logLines.length - 1].seq;
  const pre = $("log");
  pre.scrollTop = pre.scrollHeight;
}

// -- one snapshot drives everything ------------------------------------------

function render(s) {
  known = s;
  const setupHint = $("setup-hint");
  if (setupHint) setupHint.hidden = !!(s.environment && s.environment.configured);
  const step = stepFor(s);
  renderStep(step);
  renderRailNote(s);
  renderHeader(s);
  renderActions(s, step);
  renderDevice(s.device, s.vm);
  renderToast(s);
  renderScan(s.scan, s.state);
  renderReport(s.report, s.device);
}

async function getState() {
  const response = await fetch("/api/state", { cache: "no-store" });
  if (!response.ok) throw new Error(`state ${response.status}`);
  return response.json();
}

// -- live transport ----------------------------------------------------------

function liveStatus(text, cls) {
  setText("live-status", text);
  $("live-dot").className = "dot" + (cls || "");
}

function connect() {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  const url = `${scheme}://${location.host}/live?token=${encodeURIComponent(window.TRIAGE_TOKEN)}`;
  try {
    socket = new WebSocket(url);
  } catch (err) {
    liveStatus("polling", " warn");
    return;
  }
  socket.onopen = () => liveStatus("live", " on");
  socket.onmessage = (event) => {
    lastPush = Date.now();
    let message;
    try {
      message = JSON.parse(event.data);
    } catch (err) {
      return;
    }
    if (message.type === "state" && message.state) render(message.state);
    if (message.type === "log" && message.event) appendLog(message.event);
  };
  socket.onclose = () => {
    liveStatus("reconnecting", " warn");
    // the socket dropping must never freeze the display: poll straight away and
    // keep trying to get the live one back
    if (!pollTimer) pollTimer = setInterval(pollOnce, 2000);
    setTimeout(connect, 3000);
  };
  socket.onerror = () => socket.close();
}

async function pollOnce() {
  if (socket && socket.readyState === WebSocket.OPEN
      && Date.now() - lastPush < 5000) return;
  try {
    render(await getState());
  } catch (err) {
    /* the app is restarting; the socket will come back */
  }
}

// -- actions -----------------------------------------------------------------

document.addEventListener("click", async (event) => {
  const btn = event.target.closest("button[data-action]");
  if (!btn) return;
  const action = btn.dataset.action;
  const device = known && known.device ? known.device.devnode : "";
  btn.disabled = true;
  try {
    const response = await fetch(`/api/action/${action}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Triage-Token": window.TRIAGE_TOKEN },
      body: JSON.stringify({ device }),
    });
    const payload = await response.json();
    if (!response.ok) {
      // a refused action is worth saying out loud, and it must not be wiped by
      // the next snapshot, so it gets its own line under the panel
      showError(payload.error || `${action} failed`);
    } else {
      showError("");
    }
    if (payload.state) render(payload.state);
  } catch (err) {
    showError(`${action} failed: ${err}`);
  } finally {
    btn.disabled = false;
  }
});

function showError(text) {
  const el = $("stage-error");
  el.textContent = text || "";
  el.hidden = !text;
}

// -- settings: prepare the machine, flag it configured -------------------------

let settingsTimer = null;

async function loadSettings() {
  let status;
  try {
    const response = await fetch("/api/settings", {
      headers: { "X-Triage-Token": window.TRIAGE_TOKEN },
    });
    status = await response.json();
    if (!response.ok) throw new Error(status.error || response.status);
  } catch (err) {
    setText("build-status", `could not read settings: ${err}`);
    return;
  }
  const list = $("env-checks");
  list.textContent = "";
  (status.checks || []).forEach((check) => {
    const li = document.createElement("li");
    if (!check.ok) li.className = "bad";
    const dot = document.createElement("span");
    dot.className = "dot" + (check.ok ? " on" : "");
    if (!check.ok) dot.style.background = "var(--bad)";
    const label = document.createElement("span");
    label.textContent = check.label;
    const detail = document.createElement("span");
    detail.className = "detail";
    detail.textContent = check.detail || "";
    li.append(dot, label, detail);
    list.appendChild(li);
  });

  const build = status.build || {};
  const buildBtn = $("btn-build");
  buildBtn.disabled = !!build.running;
  buildBtn.textContent = build.running ? "Building…" : "Build golden image";
  setText("build-status", build.running
    ? "building now — progress lines appear below and in events"
    : (build.error || ""));
  const log = $("build-log");
  if ((build.log || []).length) {
    log.hidden = false;
    log.textContent = build.log.join("\n");
    log.scrollTop = log.scrollHeight;
  } else {
    log.hidden = true;
  }

  setText("configured-line", status.configured
    ? `flagged as configured${status.configured_at ? ` on ${status.configured_at}` : ""}`
    : "not flagged yet — flag it once the checks above are green");
  const flagBtn = $("btn-configured");
  flagBtn.textContent = status.configured ? "Unmark configured" : "Mark as configured";
  flagBtn.dataset.want = status.configured ? "0" : "1";
}

async function postSettings(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Triage-Token": window.TRIAGE_TOKEN },
    body: JSON.stringify(body || {}),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) showError(payload.error || `${path} failed`);
  await loadSettings();
}

$("btn-settings").addEventListener("click", () => {
  $("settings-dialog").showModal();
  loadSettings();
  clearInterval(settingsTimer);
  settingsTimer = setInterval(loadSettings, 2000);
});
$("btn-settings-close").addEventListener("click", () => {
  $("settings-dialog").close();
  clearInterval(settingsTimer);
});
$("settings-dialog").addEventListener("close", () => clearInterval(settingsTimer));
$("settings-dialog").addEventListener("click", (event) => {
  if (event.target === $("settings-dialog")) {
    $("settings-dialog").close();
    clearInterval(settingsTimer);
  }
});
$("btn-build").addEventListener("click", () => postSettings("/api/settings/build"));
$("btn-configured").addEventListener("click", (event) =>
  postSettings("/api/settings/configured",
               { configured: event.target.dataset.want !== "0" }));

// -- the tour: four example pages, no real state touched -------------------------

let tourPage = 1;

function showTour(page) {
  tourPage = Math.min(4, Math.max(1, page));
  document.querySelectorAll("[data-tour]").forEach((section) => {
    section.hidden = Number(section.dataset.tour) !== tourPage;
  });
  document.querySelectorAll("[data-tour-dot]").forEach((dot) => {
    dot.classList.toggle("on", Number(dot.dataset.tourDot) === tourPage);
  });
  $("btn-tour-back").disabled = tourPage === 1;
  $("btn-tour-next").textContent = tourPage === 4 ? "done" : "next";
}

$("btn-tour").addEventListener("click", () => {
  showTour(1);
  $("tour-dialog").showModal();
});
$("btn-tour-close").addEventListener("click", () => $("tour-dialog").close());
$("tour-dialog").addEventListener("click", (event) => {
  if (event.target === $("tour-dialog")) $("tour-dialog").close();
});
$("btn-tour-back").addEventListener("click", () => showTour(tourPage - 1));
$("btn-tour-next").addEventListener("click", () => {
  if (tourPage === 4) $("tour-dialog").close();
  else showTour(tourPage + 1);
});

// -- the events dialog -------------------------------------------------------

$("btn-log").addEventListener("click", () => {
  fillLog(logText());
  $("log-dialog").showModal();
  unseen = 0;
  $("log-badge").hidden = true;
  $("btn-log").classList.remove("alert");
});
$("btn-log-close").addEventListener("click", () => $("log-dialog").close());
$("log-dialog").addEventListener("click", (event) => {
  if (event.target === $("log-dialog")) $("log-dialog").close();
});
$("log-dialog").addEventListener("close", () => {
  unseen = 0;
  $("log-badge").hidden = true;
});

// -- start -------------------------------------------------------------------

(async function start() {
  try {
    const s = await getState();
    render(s);
    fillLog(s.events || []);
  } catch (err) {
    showError(`could not read the app state: ${err}`);
  }
  connect();
  pollTimer = setInterval(pollOnce, 2000);
})();