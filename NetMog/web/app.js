"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  info: null,
  devices: [],
  events: [],
  lastEventSeq: 0,
  meteringIp: null,
  scanning: false,
  defender: true,
  netLock: false,
  search: "",
  renaming: false,
};

/* ---------------- api helpers ---------------- */

async function api(path, body, method) {
  const m = method || (body ? "POST" : "GET");
  const res = await fetch(path, {
    method: m,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

/* ---------------- helpers ---------------- */

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s ?? "";
  return d.innerHTML;
}

function clock(iso) {
  const dt = new Date(iso);
  if (isNaN(dt)) return "";
  return dt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function relativeTime(iso) {
  const dt = new Date(iso);
  if (isNaN(dt)) return "—";
  const s = (Date.now() - dt.getTime()) / 1000;
  if (s < 5) return "Active Now";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function deviceIcon(d) {
  if (d.isGateway) return "🌐";
  if (d.isSelf) return "💻";
  const v = (d.vendor || "").toLowerCase();
  if (v.includes("apple")) return "💻";
  if (v.includes("samsung") || v.includes("xiaomi") || v.includes("huawei") ||
      v.includes("oneplus") || v.includes("oppo") || v.includes("vivo")) return "📱";
  if (v.includes("raspberry")) return "🖥";
  if (v.includes("intel") || v.includes("dell") || v.includes("hp") ||
      v.includes("lenovo") || v.includes("asus") || v.includes("acer")) return "💻";
  if (v.includes("tp-link") || v.includes("netgear") || v.includes("ubiquiti") ||
      v.includes("cisco") || v.includes("mikrotik")) return "🌐";
  return "🖥";
}

/* ---------------- toasts ---------------- */

function toast(msg, type = "") {
  const el = document.createElement("div");
  el.className = "toast " + type;
  el.textContent = msg;
  $("toasts").appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

/* ---------------- card HTML (main grid) ---------------- */

function cardHtml(d) {
  const stClass = d.state === 1 ? "card-cut" : d.state === 2 ? "card-meter" : "";
  const icon = deviceIcon(d);

  /* name — your own label, or the name the device announces on the network */
  const custom = d.customName || "";
  const auto = custom ? "" : d.hostName || "";
  const label = custom || auto;
  const nameCls = label
    ? `card-name editable-name${custom ? "" : " auto"}`
    : "card-name editable-name empty";
  const nameHtml = `<div class="${nameCls}" data-mac="${esc(d.mac)}" data-custom="${esc(custom)}" data-auto="${esc(auto)}" title="${custom ? "Click to rename" : "Name reported by the device — click to rename"}">${esc(label)}</div>`;

  const ipText = d.isSelf ? `${d.ip} (local)` : d.ip;

  /* tags */
  const tags = [];
  if (d.isSelf) tags.push(`<span class="tag tag-self">You</span>`);
  if (d.isGateway) tags.push(`<span class="tag tag-gw">GW</span>`);
  if (d.online === false) tags.push(`<span class="tag tag-warn">OFFLINE</span>`);
  if (d.randomizedMac) tags.push(`<span class="tag tag-warn">Rand. MAC</span>`);
  if (d.state === 1) tags.push(`<span class="tag tag-cut">✂ CUT</span>`);
  if (d.state === 2) tags.push(`<span class="tag tag-meter">METERING</span>`);
  const tagsHtml = tags.length ? `<div class="card-tags">${tags.join("")}</div>` : "";

  /* fields */
  const lastSeen = relativeTime(d.lastSeen);
  const vendor = d.vendor || "Unknown";
  const lastSeenHtml = `<div class="cfield-val" data-lastseen="${esc(d.ip)}">${lastSeen}</div>`;

  /* actions — design: Eye "Monitor" + Scissors "Cut Access" */
  let actionsHtml = "";
  if (d.isSelf || d.isGateway) {
    actionsHtml = `<span class="card-protected">PROTECTED</span>`;
  } else if (d.state === 1) {
    actionsHtml = `<button class="cbtn cbtn-restore" data-act="restore" data-ip="${d.ip}">↩ Restore</button>`;
  } else {
    actionsHtml = `<button class="cbtn" data-act="monitor" data-ip="${d.ip}">
      <svg class="cbtn-ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>
      Monitor</button>`;
    actionsHtml += `<button class="cbtn cbtn-cut" data-act="cut" data-ip="${d.ip}">
      <svg class="cbtn-ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><line x1="20" y1="4" x2="8.12" y2="15.88"/><line x1="14.47" y1="14.48" x2="20" y2="20"/><line x1="8.12" y1="8.12" x2="12" y2="12"/></svg>
      Cut Access</button>`;
  }

  return `<div class="card ${stClass}" draggable="true" data-ip="${d.ip}">
    <div class="card-head">
      <div class="card-identity">
        ${nameHtml}
        <div class="card-ip">${esc(ipText)}</div>
        <div class="card-mac">MAC: ${esc(d.mac)}</div>
      </div>
      <div class="card-head-icons">
        <svg class="card-grip" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="9" cy="5" r="1"/><circle cx="9" cy="12" r="1"/><circle cx="9" cy="19" r="1"/>
          <circle cx="15" cy="5" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="15" cy="19" r="1"/>
        </svg>
        <div class="card-dev-icon">${icon}</div>
      </div>
    </div>
    ${tagsHtml}
    <div class="card-fields">
      <div class="cfield"><div class="cfield-label">LAST SEEN</div>${lastSeenHtml}</div>
      <div class="cfield"><div class="cfield-label">VENDOR</div><div class="cfield-val">${esc(vendor)}</div></div>
    </div>
    <div class="card-actions">${actionsHtml}</div>
  </div>`;
}

/* ---------------- trusted entity HTML (right sidebar) ---------------- */

function trustedHtml(d) {
  const icon = d.isSelf ? "👤" : d.isGateway ? "🛡" : "🔗";
  const name = d.customName || d.hostName || (d.isSelf ? "This PC" : d.isGateway ? "Router" : d.ip);
  const role = d.isSelf ? "Local Machine" : d.isGateway ? "Gateway" : "";
  const vendorBit = d.vendor ? ` · ${d.vendor}` : "";

  return `<div class="tent" data-ip="${d.ip}">
    <div class="tent-icon">${icon}</div>
    <div class="tent-body">
      <div class="tent-name">${esc(name)}</div>
      <div class="tent-sub">${esc(d.ip)} · ${esc(role)}${esc(vendorBit)}</div>
    </div>
  </div>`;
}

/* ---------------- managed (killed) card HTML (left sidebar) — design's KILLED list ---------------- */

function managedCardHtml(d) {
  const name = d.customName || d.hostName || "";
  const title = name || d.ip;
  const sub = name ? `${d.ip} · ${d.mac}` : d.mac;
  return `<div class="mcard card" draggable="true" data-ip="${d.ip}">
    <span class="mcard-ico">${deviceIcon(d)}</span>
    <div class="mcard-body">
      <div class="mcard-line">
        <span class="mcard-ip">${esc(title)}</span>
        <span class="killed-badge">KILLED</span>
      </div>
      <div class="mcard-mac">${esc(sub)}</div>
    </div>
    <button class="mcard-x" data-act="restore" data-ip="${d.ip}" aria-label="Return ${esc(d.ip)} to inventory">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
      </svg>
    </button>
  </div>`;
}

/* ---------------- render ---------------- */

let lastRenderSig = "";

function deviceSig(d) {
  return [d.ip, d.state, d.customName || "", d.hostName || "", d.vendor || "",
    d.mac, d.isSelf ? 1 : 0, d.isGateway ? 1 : 0,
    Math.floor((Date.now() - new Date(d.lastSeen)) / 5000)].join("|");
}

function render() {
  const trusted = state.devices.filter((d) => d.isSelf || d.isGateway);
  const managing = state.devices.filter((d) => !d.isSelf && !d.isGateway && d.state === 1);
  let users = state.devices.filter((d) => !d.isSelf && !d.isGateway && d.state !== 1);

  if (state.search) {
    const q = state.search.toLowerCase();
    const hit = (d) =>
      (d.ip + " " + d.mac + " " + (d.hostName || "") + " " + (d.vendor || "") + " " + (d.customName || ""))
        .toLowerCase().includes(q);
    users = users.filter(hit);
  }

  /* counts */
  $("cnt-active").textContent = users.length;

  /* skip full DOM rebuild when nothing meaningful changed — only refresh time text */
  const sig = state.search + "|" + [...users, ...managing, ...trusted].map(deviceSig).join("|");
  if (sig === lastRenderSig) {
    const times = {};
    for (const d of users) times[d.ip] = relativeTime(d.lastSeen);
    for (const el of document.querySelectorAll("[data-lastseen]")) {
      const t = times[el.dataset.lastseen];
      if (t) el.textContent = t;
    }
    return;
  }
  lastRenderSig = sig;

  /* main grid */
  if (users.length) {
    $("cards-users").innerHTML = users.map(cardHtml).join("");
  } else {
    $("cards-users").innerHTML = `<div class="colempty">${
      state.search
        ? "No devices match your search."
        : "No users yet — click Scan to find devices on your network."
    }</div>`;
  }

  /* managing sidebar */
  $("cards-managing").innerHTML = managing.length
    ? managing.map(managedCardHtml).join("")
    : "";

  /* trusted sidebar */
  $("cards-trusted").innerHTML = trusted.length
    ? trusted.map(trustedHtml).join("")
    : `<div class="colempty" style="grid-column:auto">Waiting for network info…</div>`;
}

/* ---------------- render status / header stats ---------------- */

function renderStatus() {
  const gw = state.info ? state.info.gateway : "—";
  $("stat-gw").textContent = gw;

  /* scanning indicator */
  const scanBtn = $("btnScan");
  scanBtn.disabled = state.scanning;
  scanBtn.classList.toggle("scanning", state.scanning);
}

/* ---------------- polling ---------------- */

let stopped = false;

async function poll() {
  if (stopped) return;
  try {
    const data = await api("/api/devices");
    state.devices = data.devices || [];
    state.events = data.events || [];
    state.scanning = data.scanning;
    state.meteringIp = data.meteringIp;
    state.defender = data.defender !== false;
    state.netLock = !!data.netLock;

    announceNewDevices();
    syncToggles();
    renderStatus();
    renderHistory();
    if (mon.open) renderMonitor();
    if (!state.renaming) render();
  } catch (e) {
    /* lost connection — keep UI as-is */
  }
}

/* ---------------- new-device alerts + activity log ---------------- */

function announceNewDevices() {
  const events = state.events || [];
  if (!events.length) return;
  const newest = Math.max(...events.map((e) => e.seq));
  if (state.lastEventSeq === 0) {
    /* first poll after load: show the backlog in the log, do not toast it */
    state.lastEventSeq = newest;
    return;
  }
  for (const e of events) {
    if (e.seq <= state.lastEventSeq) continue;
    if (e.kind === "device-new") toast(`New device — ${e.message}`, "warn");
    else if (e.kind === "netlock") toast(e.message, "err");
  }
  state.lastEventSeq = newest;
}

let lastHistorySig = "";

/* name column: what the event recorded, else the device's current name */
function eventName(e) {
  if (e.name) return e.name;
  /* app-level lines are about the machine itself, not a device */
  if (e.kind === "app" || !e.mac) return "";
  const d = state.devices.find((x) => x.mac === e.mac);
  if (!d) return "";
  return d.customName || d.hostName || d.ip || "";
}

function renderHistory() {
  const events = state.events || [];
  const names = state.devices.map((d) => d.mac + (d.customName || "") + (d.hostName || "")).join("|");
  const sig = events.map((e) => e.seq).join(",") + " | " + names;
  if (sig === lastHistorySig) return;
  lastHistorySig = sig;

  const el = $("history-list");
  if (!events.length) {
    el.innerHTML = `<div class="colempty" style="grid-column:auto">No activity yet.</div>`;
    return;
  }
  el.innerHTML = events
    .slice()
    .reverse()
    .map((e) => {
      const name = eventName(e);
      return `<div class="hrow">
        <span class="hrow-dot ${esc(e.kind)}"></span>
        ${name ? `<span class="hrow-name" title="${esc(e.mac || e.ip)}">${esc(name)}</span>` : ""}
        <span class="hrow-txt">${esc(e.message)}</span>
        <span class="hrow-time">${esc(clock(e.at))}</span>
      </div>`;
    })
    .join("");
}

/* ---------------- actions ---------------- */

async function doScan() {
  try {
    await api("/api/scan", null, "POST");
  } catch {
    toast("Could not start scan", "err");
  }
}

async function act(verb, ip) {
  try {
    const r = await api("/api/" + verb, { ip });
    if (!r.ok) {
      toast(r.error ? `Cannot ${verb} ${ip}: ${r.error}` : `Cannot ${verb} ${ip}`, "err");
    }
  } catch {
    toast("Request failed", "err");
  }
}

async function toggleMonitor(ip) {
  try {
    const r = await api("/api/monitor", { ip });
    if (!r.ok) {
      toast("Monitor failed (run Scan first?)", "err");
    }
  } catch {
    toast("Request failed", "err");
  }
}

/* ---------------- bandwidth monitor dialog (design's LIVE BANDWIDTH) ---------------- */

const MON_LEN = 16;
const mon = {
  open: false,
  ip: null,
  down: Array(MON_LEN).fill(0),
  up: Array(MON_LEN).fill(0),
};

async function openMonitor(ip) {
  mon.ip = ip;
  mon.down = Array(MON_LEN).fill(0);
  mon.up = Array(MON_LEN).fill(0);

  const dev = state.devices.find((d) => d.ip === ip);
  $("mon-ip").textContent = ip;
  $("mon-mac").textContent = `${dev ? dev.mac : "—"} • ${dev && dev.vendor ? dev.vendor : "Unknown"}`;
  $("mon-limit").value = dev && dev.limitKbps ? dev.limitKbps : "";
  $("mon-drop").textContent = "";
  $("mon-overlay").hidden = false;
  mon.open = true;

  if (!dev || dev.state !== 2) await toggleMonitor(ip);
  renderMonitor();
}

function closeMonitor() {
  if (!mon.open) return;
  mon.open = false;
  mon.ip = null;
  $("mon-overlay").hidden = true;
  if (state.meteringIp) api("/api/monitorstop", null, "POST");
}

function fmtRate(v) {
  const kb = v / 8;
  if (kb >= 1000) return { v: (kb / 1024).toFixed(1), u: "MB" };
  return { v: kb.toFixed(1), u: "KB" };
}
function rateStr(v) { const f = fmtRate(v); return `${f.v} ${f.u}`; }

function renderMonitor() {
  const md = state.devices.find((d) => d.ip === mon.ip && d.state === 2);
  const down = md ? md.downKbps || 0 : 0;
  const up = md ? md.upKbps || 0 : 0;
  mon.down = [...mon.down.slice(1), down];
  mon.up = [...mon.up.slice(1), up];

  const ch = (arr, valEl, unitEl, peakEl, avgEl, sparkEl, totalEl) => {
    const cur = arr[arr.length - 1];
    const peak = Math.max(...arr);
    const avg = arr.reduce((a, b) => a + b, 0) / arr.length;
    const f = fmtRate(cur);
    $(valEl).textContent = f.v;
    $(unitEl).textContent = f.u;
    $(peakEl).textContent = `PEAK ${rateStr(peak)}`;
    $(avgEl).textContent = `AVG ${rateStr(avg)}`;
    $(sparkEl).innerHTML = sparkSvg(arr);
    if (totalEl) $(totalEl).textContent = rateStr(mon.down[mon.down.length - 1] + mon.up[mon.up.length - 1]);
  };
  ch(mon.down, "mon-down-val", "mon-down-unit", "mon-down-peak", "mon-down-avg", "mon-down-spark");
  ch(mon.up, "mon-up-val", "mon-up-unit", "mon-up-peak", "mon-up-avg", "mon-up-spark", "mon-total");

  const dropped = md ? md.droppedFrames || 0 : 0;
  $("mon-drop").textContent = dropped > 0 ? `DROPPED ${dropped}` : "";
}

/* ---------------- bandwidth limit ---------------- */

async function applyLimit() {
  if (!mon.ip) return;
  const raw = $("mon-limit").value.trim();
  const kbps = raw === "" ? 0 : Math.max(0, Math.round(Number(raw) || 0));
  try {
    const r = await api("/api/limit", { ip: mon.ip, kbps });
    if (!r.ok) {
      toast("Could not set the limit", "err");
      return;
    }
    const dev = state.devices.find((d) => d.ip === mon.ip);
    if (dev) dev.limitKbps = kbps;
    toast(kbps > 0 ? `Limited to ${kbps} kbps` : "Limit removed");
  } catch {
    toast("Request failed", "err");
  }
}

$("mon-limit-apply").addEventListener("click", applyLimit);
$("mon-limit").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); applyLimit(); }
});

function sparkSvg(data) {
  const max = Math.max(...data, 1);
  const pts = data
    .map((v, i) => `${(i / (data.length - 1)) * 100},${100 - (v / max) * 92}`)
    .join(" ");
  return `<svg viewBox="0 0 100 100" preserveAspectRatio="none" class="spark-svg">
    <polyline points="${pts}" fill="none" stroke="currentColor" stroke-width="1.4" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>
    <polygon points="0,100 ${pts} 100,100" fill="currentColor" opacity="0.12"/>
  </svg>`;
}

$("mon-close").addEventListener("click", closeMonitor);
$("mon-overlay").addEventListener("click", (e) => { if (e.target === $("mon-overlay")) closeMonitor(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && mon.open) closeMonitor(); });

/* ---------------- toggles ---------------- */

function syncToggles() {
  $("tgl-defender").classList.toggle("on", state.defender);
  $("tgl-netlock").classList.toggle("on", state.netLock);
}

$("tgl-defender").addEventListener("click", async () => {
  const on = !state.defender;
  try {
    const r = await api("/api/defender", { on });
    state.defender = r.on !== false;
    syncToggles();
  } catch { toast("Request failed", "err"); }
});

$("tgl-netlock").addEventListener("click", async () => {
  const on = !state.netLock;
  try {
    const r = await api("/api/netlock", { on });
    state.netLock = !!r.on;
    syncToggles();
  } catch { toast("Request failed", "err"); }
});

/* ---------------- events ---------------- */

$("btnScan").addEventListener("click", doScan);
$("search").addEventListener("input", (e) => { state.search = e.target.value.trim(); render(); });
$("btnCutAll").addEventListener("click", async () => {
  try {
    const result = await api("/api/killall", null, "POST");
    if (result.ok) {
      toast(`Killed ${result.count || 0} devices`);
      poll();
    } else {
      toast("Kill All failed", "err");
    }
  } catch {
    toast("Kill All request failed", "err");
  }
});
$("btnRestoreAll").addEventListener("click", async () => {
  try {
    const result = await api("/api/restoreall", null, "POST");
    if (result.ok) {
      toast(`Restored ${result.count || 0} devices`);
      poll();
    } else {
      toast("Restore All failed", "err");
    }
  } catch {
    toast("Restore All request failed", "err");
  }
});

/* keyboard shortcut CMD+K for search */
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "k") {
    e.preventDefault();
    $("search").focus();
  }
});

/* card click delegation */
document.querySelectorAll(".cards").forEach((col) => {
  col.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-act]");
    if (btn) {
      const { act: verb, ip } = btn.dataset;
      if (verb === "monitor") openMonitor(ip);
      else act(verb === "cut" ? "kill" : verb, ip);
      return;
    }
    const editableName = e.target.closest(".editable-name");
    if (editableName) {
      startRename(editableName);
      return;
    }
  });
});

/* ---------------- inline rename ---------------- */

function startRename(el) {
  const mac = el.dataset.mac;
  const input = document.createElement("input");
  input.type = "text";
  /* start from your own label; the detected name is only the placeholder */
  input.value = el.dataset.custom || "";
  input.placeholder = el.dataset.auto || "Device name";
  el.replaceWith(input);
  state.renaming = true;
  input.focus();
  input.select();

  const finish = () => {
    if (!state.renaming) return;
    state.renaming = false;
    render();
  };

  const save = async () => {
    try {
      const name = input.value.trim();
      await api("/api/rename", { mac, name });
      const d = state.devices.find((x) => x.mac === mac);
      if (d) d.customName = name;
      toast(name ? `Renamed to "${name}"` : "Name cleared");
    } catch {
      toast("Rename failed", "err");
    } finally {
      finish();
    }
  };

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); save(); }
    if (e.key === "Escape") { finish(); }
  });
  input.addEventListener("blur", () => { if (state.renaming) save(); });
}

/* ---------------- name-device dialog (from the context menu) ----------------
   The inline editor only exists on a visible name line, so a device with no
   name yet — or one sitting in the KILLED rail — is named here instead. */

const rn = { mac: "" };

function openRenameDialog(dev) {
  rn.mac = dev.mac;
  $("rename-sub").textContent = `${dev.ip} · ${dev.mac}`;
  const input = $("rename-input");
  input.value = dev.customName || "";
  input.placeholder = dev.hostName ? `${dev.hostName} (detected)` : "Device name";
  $("rename-overlay").hidden = false;
  input.focus();
  input.select();
}

function closeRenameDialog() {
  $("rename-overlay").hidden = true;
  rn.mac = "";
}

async function saveRenameDialog() {
  if (!rn.mac) return;
  const mac = rn.mac;
  const name = $("rename-input").value.trim();
  closeRenameDialog();
  try {
    await api("/api/rename", { mac, name });
    const d = state.devices.find((x) => x.mac === mac);
    if (d) d.customName = name;
    toast(name ? `Named "${name}"` : "Name cleared");
  } catch {
    toast("Rename failed", "err");
  }
  poll();
}

$("rename-save").addEventListener("click", saveRenameDialog);
$("rename-cancel").addEventListener("click", closeRenameDialog);
$("rename-close").addEventListener("click", closeRenameDialog);
$("rename-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); saveRenameDialog(); }
  if (e.key === "Escape") { e.preventDefault(); closeRenameDialog(); }
});
$("rename-overlay").addEventListener("click", (e) => {
  if (e.target === $("rename-overlay")) closeRenameDialog();
});

/* ---------------- drag & drop (Lovable design behavior) ---------------- */

let dragIp = null;
let dragOverCount = 0;
const mainEl = document.querySelector(".center");

document.addEventListener("dragstart", (e) => {
  const card = e.target.closest(".card");
  if (!card) return;
  dragIp = card.dataset.ip;
  card.classList.add("dragging");
  $("zone-managing").classList.add("has-drag");
  e.dataTransfer.effectAllowed = "move";
  e.dataTransfer.setData("text/plain", dragIp);
});

document.addEventListener("dragend", () => {
  dragIp = null;
  dragOverCount = 0;
  document.querySelectorAll(".dragging").forEach((x) => x.classList.remove("dragging"));
  $("zone-managing").classList.remove("has-drag", "over");
  setDropText(false);
  mainEl.classList.remove("dropactive");
});

function setDropText(active) {
  const t = $("dz-text");
  if (!t) return;
  t.textContent = active ? "Release to kill" : "Drop to kill";
}

/* drop on dropzone = cut */
const zone = $("zone-managing");
zone.addEventListener("dragover", (e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; zone.classList.add("over"); setDropText(true); });
zone.addEventListener("dragenter", (e) => { e.preventDefault(); dragOverCount++; zone.classList.add("over"); setDropText(true); });
zone.addEventListener("dragleave", () => { dragOverCount--; if (dragOverCount <= 0) { dragOverCount = 0; zone.classList.remove("over"); setDropText(false); } });
zone.addEventListener("drop", (e) => {
  e.preventDefault();
  dragOverCount = 0;
  zone.classList.remove("over");
  setDropText(false);
  const ip = e.dataTransfer.getData("text/plain") || dragIp;
  const dev = state.devices.find((d) => d.ip === ip);
  if (!dev) return;
  if (dev.isSelf || dev.isGateway) { toast("This device is protected", "err"); return; }
  if (dev.state !== 1) act("kill", ip);
});

/* drop on main = restore (design: moveToInventory) */
let usersOverCount = 0;
mainEl.addEventListener("dragover", (e) => {
  const dev = state.devices.find((d) => d.ip === dragIp);
  if (dev) { e.preventDefault(); e.dataTransfer.dropEffect = "move"; mainEl.classList.add("dropactive"); }
});
mainEl.addEventListener("dragenter", (e) => { e.preventDefault(); usersOverCount++; });
mainEl.addEventListener("dragleave", () => { usersOverCount--; if (usersOverCount <= 0) { usersOverCount = 0; mainEl.classList.remove("dropactive"); } });
mainEl.addEventListener("drop", (e) => {
  e.preventDefault();
  mainEl.classList.remove("dropactive");
  const ip = e.dataTransfer.getData("text/plain") || dragIp;
  const dev = state.devices.find((d) => d.ip === ip);
  if (dev && dev.state === 1) act("restore", ip);
});

/* ---------------- context menu ---------------- */

const ctx = $("ctx");
document.addEventListener("contextmenu", (e) => {
  const card = e.target.closest(".card, .tent");
  if (!card) return;
  e.preventDefault();
  const ip = card.dataset.ip;
  const dev = state.devices.find((d) => d.ip === ip);
  if (!dev) return;

  ctx.innerHTML = "";
  const add = (label, fn, cls) => {
    const d = document.createElement("div");
    d.textContent = label;
    if (cls) d.style.color = cls;
    d.addEventListener("click", () => { ctx.style.display = "none"; fn(); });
    ctx.appendChild(d);
  };
  const sep = () => { const s = document.createElement("div"); s.className = "sep"; ctx.appendChild(s); };

  if (dev.isSelf || dev.isGateway) {
    add("This device is protected", () => {});
  } else if (dev.state === 1) {
    add("Restore device", () => act("restore", ip), "var(--ok)");
  } else {
    add("Cut device", () => act("kill", ip), "var(--danger)");
  }
  if (!dev.isSelf && !dev.isGateway) {
    add(state.meteringIp === ip ? "Stop monitoring" : "Monitor bandwidth", () => toggleMonitor(ip), "var(--warn)");
  }
  sep();
  /* works on any card: main grid, the KILLED rail, or the trusted rail */
  add(dev.customName ? "Rename device" : "Name this device", () => openRenameDialog(dev));

  ctx.style.left = Math.min(e.clientX, innerWidth - 210) + "px";
  ctx.style.top = Math.min(e.clientY, innerHeight - 200) + "px";
  ctx.style.display = "block";
});
document.addEventListener("click", () => (ctx.style.display = "none"));

/* ---------------- quit (restores every cut device) ---------------- */

$("btnQuit").addEventListener("click", async () => {
  if (!confirm("Quit NetMog?\n\nEvery cut device is restored first.")) return;
  stopped = true;
  try {
    await api("/api/shutdown", null, "POST");
  } catch {
    /* the server may close the socket before the reply lands */
  }
  toast("NetMog stopped — all cut devices restored", "ok");
  document.title = "NETMOG — stopped";
});

/* ---------------- init ---------------- */

(async function init() {
  try {
    state.info = await api("/api/info");
    $("stat-gw").textContent = state.info.gateway;
  } catch {
    /* server unreachable */
  }
  poll();
  setInterval(poll, 1000);
})();
