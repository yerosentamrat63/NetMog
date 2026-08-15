"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  info: null,
  devices: [],
  checked: new Set(),
  selectedIp: null,
  meteringIp: null,
  scanning: false,
  killed: 0,
  packets: 0,
  defender: true,
  netLock: false,
  search: "",
  tab: "devices",
  records: [],
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

/* ---------------- toasts ---------------- */

function toast(msg, type = "") {
  const el = document.createElement("div");
  el.className = "toast " + type;
  el.textContent = msg;
  $("toasts").appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

/* ---------------- records ---------------- */

function log(kind, text) {
  state.records.unshift({ t: new Date(), kind, text });
  state.records = state.records.slice(0, 200);
  renderRecords();
}

function renderRecords() {
  const wrap = $("records");
  if (!state.records.length) {
    wrap.innerHTML = `<div class="colempty">No events yet — cut, restore and scan actions will appear here.</div>`;
    return;
  }
  wrap.innerHTML = state.records.map((r) => {
    const t = r.t.toLocaleTimeString();
    return `<div class="rec ${r.kind}"><span class="t">${t}</span><span class="txt">${r.text}</span></div>`;
  }).join("");
}

/* ---------------- rendering ---------------- */

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s ?? "";
  return d.innerHTML;
}

const fmtTime = (iso) => {
  const dt = new Date(iso);
  return isNaN(dt) ? "—" : dt.toLocaleTimeString();
};

function cardHtml(d) {
  const cls = d.isSelf || d.isGateway ? "trustcard" : d.state === 1 ? "cutcard" : d.state === 2 ? "metercard" : "";
  const name = d.isSelf
    ? `<span class="self">${esc(d.hostName || "This PC")}</span>`
    : d.isGateway
      ? `<span class="gw">Router</span>`
      : esc(d.hostName || "<unknown>");

  const tags = [];
  if (d.isSelf) tags.push(`<span class="tag blue">You</span>`);
  if (d.isGateway) tags.push(`<span class="tag blue">GW</span>`);
  if (d.randomizedMac) tags.push(`<span class="tag warn">Rand. MAC</span>`);
  if (d.state === 1) tags.push(`<span class="tag bad">✂ Cut</span>`);
  if (d.state === 2) tags.push(`<span class="tag warn">Metering</span>`);
  if (d.vendor) tags.push(`<span class="tag ok">${esc(d.vendor)}</span>`);

  const ip = d.isSelf ? `${d.ip} (local)` : d.ip;
  const rates = d.state === 2
    ? `<div class="rates"><span class="d">▼ ${d.downKbps > 0 ? d.downKbps.toFixed(1) : "0.0"} KB/s</span><span class="u">▲ ${d.upKbps > 0 ? d.upKbps.toFixed(1) : "0.0"} KB/s</span></div>`
    : "";

  let acts = "";
  if (d.isSelf || d.isGateway) {
    acts = `<span class="tag blue" style="align-self:center">protected</span>`;
  } else if (d.state === 1) {
    acts = `<button class="ok" data-act="restore" data-ip="${d.ip}">Restore</button>`;
  } else {
    acts = `<button class="danger" data-act="cut" data-ip="${d.ip}">✂ Cut</button>`;
  }
  acts += d.isSelf || d.isGateway
    ? ""
    : d.state === 2
      ? `<button class="warn" data-act="monitor" data-ip="${d.ip}">⦿ Stop</button>`
      : `<button class="warn" data-act="monitor" data-ip="${d.ip}">⦿ Monitor</button>`;

  return `<div class="card ${cls}" draggable="true" data-ip="${d.ip}">
    <div class="cname">${name}${tags.join("")}</div>
    <div class="crow"><b>IP</b><span class="v masked">${esc(ip)}</span></div>
    <div class="crow"><b>MAC</b><span class="v masked">${esc(d.mac)}</span>
      <button class="copy" title="Copy MAC" data-copy="${esc(d.mac)}">⧉</button></div>
    <div class="crow"><b>LAST</b><span>${fmtTime(d.lastSeen)}</span></div>
    ${rates}
    <div class="cacts">${acts}</div>
  </div>`;
}

function render() {
  const trusted = state.devices.filter((d) => d.isSelf || d.isGateway);
  const managing = state.devices.filter((d) => !d.isSelf && !d.isGateway && d.state === 1);
  let users = state.devices.filter((d) => !d.isSelf && !d.isGateway && d.state !== 1);

  if (state.search) {
    const q = state.search.toLowerCase();
    const hit = (d) => (d.ip + " " + d.mac + " " + (d.hostName || "") + " " + (d.vendor || "")).toLowerCase().includes(q);
    users = users.filter(hit);
  }

  const h = (cards, fallback) => cards.length
    ? cards.map(cardHtml).join("")
    : `<div class="colempty">${fallback}</div>`;

  $("cards-users").innerHTML = h(users, state.search
    ? "No devices match your search."
    : "No users yet — click Scan to find devices on your network.");
  $("cards-managing").innerHTML = h(managing, "Drop devices here to cut their access.");
  $("cards-trusted").innerHTML = h(trusted, "This PC and the gateway live here.");

  $("cnt-users").textContent = users.length;
  $("cnt-managing").textContent = managing.length;
  $("cnt-trusted").textContent = trusted.length;
}

function renderStatus() {
  const ip = state.info ? `${state.info.localIp}` : "?";
  const gw = state.info ? `${state.info.gateway}` : "?";
  $("statusline").innerHTML =
    (state.scanning ? `<span class="sc">Scanning network…</span> · ` : "") +
    `Netcut running under Admin · you <span class="on">${ip}</span> · GW <span class="on">${gw}</span>` +
    ` · pkts <span class="on">${state.packets.toLocaleString()}</span>` +
    ` · cut ${state.killed}` +
    (state.netLock ? ` · <span class="sc">netLock ON</span>` : "");
  $("pkts").textContent = `${state.packets.toLocaleString()} pkts`;
}

/* ---------------- polling ---------------- */

async function poll() {
  try {
    const data = await api("/api/devices");
    state.devices = data.devices || [];
    state.scanning = data.scanning;
    state.killed = data.killed;
    state.packets = data.packets;
    state.meteringIp = data.meteringIp;
    state.defender = data.defender !== false;
    state.netLock = !!data.netLock;

    $("btnScan").disabled = state.scanning;
    $("btnRefresh").disabled = state.scanning;
    syncToggles();

    const ips = new Set(state.devices.map((d) => d.ip));
    [...state.checked].forEach((ip) => { if (!ips.has(ip)) state.checked.delete(ip); });
    if (state.selectedIp && !ips.has(state.selectedIp)) state.selectedIp = null;

    render();
    renderStatus();
  } catch (e) {
    $("statusline").textContent = "Lost connection to server";
  }
}

/* ---------------- actions ---------------- */

async function doScan() {
  try {
    await api("/api/scan", null, "POST");
    log("warn", "Scan started — probing the network for devices…");
  } catch {
    toast("Could not start scan", "err");
  }
}

async function act(verb, ip, name) {
  try {
    const r = await api("/api/" + verb, { ip });
    if (r.ok) {
      log(verb === "kill" ? "cut" : "restore",
        verb === "kill"
          ? `Cut <b>${esc(name || ip)}</b> (${ip})`
          : `Restored <b>${esc(name || ip)}</b> (${ip})`);
    } else {
      toast(r.error ? `Cannot ${verb} ${ip}: ${r.error}` : `Cannot ${verb} ${ip}`, "err");
    }
  } catch {
    toast("Request failed", "err");
  }
}

async function toggleMonitor(ip, name) {
  try {
    const r = await api("/api/monitor", { ip });
    if (r.ok) {
      log("warn", r.metering
        ? `Metering <b>${esc(name || ip)}</b> (${ip}) — watching bandwidth`
        : `Stopped metering <b>${esc(name || ip)}</b> (${ip})`);
    } else {
      toast("Monitor failed (run Scan first?)", "err");
    }
  } catch {
    toast("Request failed", "err");
  }
}

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
    log("warn", `Defender turned <b>${state.defender ? "ON" : "OFF"}</b>`);
  } catch { toast("Request failed", "err"); }
});

$("tgl-netlock").addEventListener("click", async () => {
  const on = !state.netLock;
  try {
    const r = await api("/api/netlock", { on });
    state.netLock = !!r.on;
    syncToggles();
    log("warn", `netLock turned <b>${state.netLock ? "ON" : "OFF"}</b>` + (state.netLock ? " — new devices will be cut automatically." : ""));
  } catch { toast("Request failed", "err"); }
});

/* ---------------- events ---------------- */

$("btnScan").addEventListener("click", doScan);
$("btnRefresh").addEventListener("click", doScan);
$("search").addEventListener("input", (e) => { state.search = e.target.value.trim(); render(); });
$("hideip").addEventListener("change", (e) => document.body.classList.toggle("hideip", e.target.checked));
$("btnCutAll").addEventListener("click", async () => { await api("/api/killall", null, "POST"); log("cut", "Cut <b>all</b> devices"); });
$("btnRestoreAll").addEventListener("click", async () => { await api("/api/restoreall", null, "POST"); log("restore", "Restored <b>all</b> devices"); });
$("btnExit").addEventListener("click", async () => {
  toast("Shutting down…");
  await api("/api/shutdown", null, "POST");
});

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    state.tab = btn.dataset.tab;
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tabpage").forEach((p) => p.classList.toggle("active", p.id === "page-" + state.tab));
  });
});

function devName(ip) {
  const d = state.devices.find((x) => x.ip === ip);
  return d ? d.hostName || d.ip : ip;
}

document.querySelectorAll(".cards").forEach((col) => {
  col.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-act]");
    const copy = e.target.closest("button[data-copy]");
    if (copy) {
      navigator.clipboard.writeText(copy.dataset.copy).then(() => toast("MAC copied"));
      return;
    }
    if (btn) {
      const { act: verb, ip } = btn.dataset;
      if (verb === "monitor") toggleMonitor(ip, devName(ip));
      else act(verb === "cut" ? "kill" : verb, ip, devName(ip));
      return;
    }
    const card = e.target.closest(".card");
    if (card) {
      state.selectedIp = card.dataset.ip;
      render();
    }
  });
});

/* drag & drop: users -> managing = cut, managing -> users = restore */
let dragIp = null;
document.addEventListener("dragstart", (e) => {
  const card = e.target.closest(".card");
  if (!card) return;
  dragIp = card.dataset.ip;
  card.classList.add("dragging");
  e.dataTransfer.effectAllowed = "move";
  e.dataTransfer.setData("text/plain", dragIp);
});
document.addEventListener("dragend", () => {
  dragIp = null;
  document.querySelectorAll(".dragging").forEach((x) => x.classList.remove("dragging"));
  $("zone-managing").classList.remove("over");
  $("cards-users").classList.remove("dropok");
  $("cards-managing").classList.remove("dropok");
});

$("zone-managing").addEventListener("dragover", (e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; $("zone-managing").classList.add("over"); });
$("zone-managing").addEventListener("dragleave", () => $("zone-managing").classList.remove("over"));
$("zone-managing").addEventListener("drop", (e) => {
  e.preventDefault();
  $("zone-managing").classList.remove("over");
  const ip = e.dataTransfer.getData("text/plain") || dragIp;
  const dev = state.devices.find((d) => d.ip === ip);
  if (!dev) return;
  if (dev.isSelf || dev.isGateway) { toast("This device is protected", "err"); return; }
  if (dev.state !== 1) act("kill", ip, dev.hostName || ip);
});

$("cards-users").addEventListener("dragover", (e) => {
  const dev = state.devices.find((d) => d.ip === dragIp);
  if (dev && dev.state === 1) { e.preventDefault(); e.dataTransfer.dropEffect = "move"; $("cards-users").classList.add("dropok"); }
});
$("cards-users").addEventListener("dragleave", () => $("cards-users").classList.remove("dropok"));
$("cards-users").addEventListener("drop", (e) => {
  e.preventDefault();
  $("cards-users").classList.remove("dropok");
  const ip = e.dataTransfer.getData("text/plain") || dragIp;
  const dev = state.devices.find((d) => d.ip === ip);
  if (dev && dev.state === 1) act("restore", ip, dev.hostName || ip);
});

/* context menu */
const ctx = $("ctx");
document.addEventListener("contextmenu", (e) => {
  const card = e.target.closest(".card");
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
    sep();
  } else if (dev.state === 1) {
    add("Restore device", () => act("restore", ip, dev.hostName || ip), "var(--ok)");
  } else {
    add("Cut device", () => act("kill", ip, dev.hostName || ip), "var(--bad)");
  }
  if (!dev.isSelf && !dev.isGateway) {
    add(state.meteringIp === ip ? "Stop monitoring" : "Monitor bandwidth", () => toggleMonitor(ip, dev.hostName || ip), "var(--warn)");
  }
  sep();
  add("Copy MAC", () => navigator.clipboard.writeText(dev.mac));
  add("Copy IP", () => navigator.clipboard.writeText(dev.ip));

  ctx.style.left = Math.min(e.clientX, innerWidth - 210) + "px";
  ctx.style.top = Math.min(e.clientY, innerHeight - 200) + "px";
  ctx.style.display = "block";
});
document.addEventListener("click", () => (ctx.style.display = "none"));

/* ---------------- init ---------------- */

(async function init() {
  try {
    state.info = await api("/api/info");
    $("netinfo").innerHTML =
      `<b>You</b> ${state.info.localIp} <span style="opacity:.45">·</span> <b>GW</b> ${state.info.gateway}` +
      ` <span style="opacity:.45">·</span> ${esc(state.info.adapter)}`;
  } catch {
    $("netinfo").textContent = "server unreachable";
  }
  log("warn", "Connected to NetcutClone server");
  poll();
  setInterval(poll, 1000);
})();