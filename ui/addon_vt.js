/* OmniShield add-on 1.9 - VirusTotal page, settings, quota meter and "Is this safe?" integration */
(function () {
"use strict";
const Q = s => document.querySelector(s), QA = s => [...document.querySelectorAll(s)];
const E = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fn = n => typeof window[n] === "function" ? window[n] : null;
const say = (m, k = "check") => fn("toast") ? toast(m, k) : console.log(m);
const pg = () => { try { return page; } catch { return ""; } };
const goto = p => fn("go") && go(p);
const n0 = n => Number(n || 0).toLocaleString();
async function J(u, body) {
  const csrf = window._csrfToken ? {"X-CSRF-Token": window._csrfToken} : {};
  const r = await fetch(u, body === undefined ? {cache: "no-store", headers: csrf} : {method: "POST", headers: {"Content-Type": "application/json", ...csrf}, body: JSON.stringify(body)});

  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(typeof j.detail === "string" ? j.detail : r.statusText); e.status = r.status; e.data = j; throw e; }
  return j;
}
const MY = {
  vt: '<rect x="3" y="3" width="18" height="18" rx="4"/><path d="m8 7 6 5-6 5M14 17h3"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  vtnav: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M8 9h8l-4 3 4 3H8"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  hash: '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>', key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  up: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>', ext: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5"/>', check: '<path d="M20 6 9 17l-5-5"/>', x: '<path d="M18 6 6 18M6 6l12 12"/>',
  alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v4h1"/>', shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  q: '<circle cx="12" cy="12" r="9"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01"/>', lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  ban: '<circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/>', clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  stop: '<rect x="5" y="5" width="14" height="14" rx="2"/>', trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>'};
try { if (typeof I === "object") for (const k in MY) if (!I[k]) I[k] = MY[k]; } catch {}
const IC = (n, a = "") => `<svg viewBox="0 0 24 24" ${a}>${MY[n] || (typeof I === "object" && I[n]) || MY.info}</svg>`;
const ago2 = t => fn("ago") ? ago(t) : new Date(t).toLocaleString();
const fname2 = p => String(p).split(/[\\/]/).pop();
const tLocal = iso => new Date(iso).toLocaleTimeString([], {hour: "numeric", minute: "2-digit"});
const dLocal = iso => new Date(iso).toLocaleDateString([], {day: "numeric", month: "short"});
const fsz = b => fn("fmtSize") ? fmtSize(b) : (b / 1048576).toFixed(1) + " MB";

/* ---- labels in the rest of the app ---- */
try { if (typeof SRC === "object") SRC.virustotal = ["VirusTotal", "vt"]; } catch {}
try { if (typeof ENG === "object") ENG.virustotal = "VirusTotal"; } catch {}
try { if (typeof ENG_COLOR === "object") ENG_COLOR.virustotal = "#394eff"; } catch {}
try { if (typeof JOB === "object") JOB.virustotal = ["vtnav", "VirusTotal check"]; } catch {}
try { PAGES.vt = ["VirusTotal", "Check files, folders, links and websites with 70+ security companies"]; } catch {}
const fEng = Q("#fEng");
if (fEng && !fEng.querySelector('option[value="virustotal"]')) fEng.insertAdjacentHTML("beforeend", '<option value="virustotal">VirusTotal</option>');

/* ---- nav + sidebar meter ---- */
const nav = document.createElement("a"); nav.dataset.p = "vt";
nav.innerHTML = IC("vtnav") + '<span class="lbl">VirusTotal</span>'; nav.onclick = () => goto("vt");
const after = Q('.nav a[data-p="checkup"]') || Q('.nav a[data-p="users"]') || Q('.nav a[data-p="check"]');
after ? after.after(nav) : Q(".nav") && Q(".nav").append(nav);
if (fn("moveInd")) requestAnimationFrame(moveInd);
const side = document.createElement("div"); side.className = "vt-side hide"; side.title = "VirusTotal lookups left today";
side.onclick = () => goto("vt");
(Q("#rtSide") || Q(".nav")).after(side);

Q("main").insertAdjacentHTML("beforeend", `<section id="p-vt" class="hide">
  <div class="head"><div class="vt-hero"><div class="vt-logo">${IC("vt")}</div><div><h1>VirusTotal</h1><p>Ask 70+ antivirus companies about a file, folder, link, website or IP address.</p></div></div>
    <span class="vt-cost" id="vtHeadCost"></span></div>
  <div id="vtBody"></div></section>`);

/* ================= state ================= */
let VT = {st: null, tab: "file", last: null, job: null, retry: null, histAll: false};
const TABS = [["file", "file", "File"], ["folder", "folder", "Folder"], ["url", "link", "Link"], ["site", "globe", "Website / IP"], ["hash", "hash", "Fingerprint"]];

async function refreshStatus() {
  try { VT.st = await J("/api/vt/status"); } catch { return null; }
  drawSide(); return VT.st;
}
function drawSide() {
  const s = VT.st; if (!s) return;
  const hc = Q("#vtHeadCost"); if (hc) hc.innerHTML = s.configured ? `${IC("clock")}${n0(s.usage.day.left)} lookups left today` : "";
  side.classList.toggle("hide", !s.configured);
  if (!s.configured) return;
  const d = s.usage.day, left = d.left, pct = d.limit ? left / d.limit * 100 : 0;
  side.className = "vt-side" + (left <= 0 ? " out" : pct < 20 ? " low" : "");
  side.innerHTML = `<div class="r">${IC("vtnav")}<b>VirusTotal</b><span>${n0(left)} left</span></div><div class="tr"><i style="width:${pct}%"></i></div>`;
  side.title = `VirusTotal today: ${n0(d.used)} of ${n0(d.limit)} used · ${n0(s.usage.month.left)} left this month`;
}

/* ================= quota meters ================= */
function meters(u, withSync = true) {
  const row = (lbl, sub, used, limit, mark) => {
    const p = limit ? Math.min(100, used / limit * 100) : 0, left = Math.max(0, limit - used);
    const cls = left <= 0 ? "bad" : p >= 80 ? "warn" : "";
    return `<div class="row"><div class="lbl"><b>${lbl}</b><small>${sub}</small></div>
      <div class="bar"><i class="${cls}" style="width:${p}%"></i>${mark != null && limit ? `<em style="left:calc(${Math.max(0, (limit - mark) / limit * 100)}% - 1px)" title="Reserve for your own checks starts here"></em>` : ""}</div>
      <div class="num"><b>${n0(left)}</b> left<span>${n0(used)} of ${n0(limit)} used</span></div></div>`;
  };
  const m = u.minute, dots = `<span class="vt-dots">${Array.from({length: Math.min(m.limit, 12)}, (_, i) => `<i class="${i < m.left ? "" : "u"}"></i>`).join("")}</span>`;
  return `<div class="vtq">
    <div class="row"><div class="lbl"><b>This minute</b><small>${u.wait > 0 ? `next in ${Math.ceil(u.wait)} s` : "ready"}</small></div><div>${dots}</div><div class="num"><b>${m.left}</b> of ${m.limit}<span>per minute</span></div></div>
    ${row("Today", `resets ${tLocal(u.day.resets)}`, u.day.used, u.day.limit, u.reserve)}
    ${row("This month", `resets ${dLocal(u.month.resets)}`, u.month.used, u.month.limit)}
  </div>${withSync ? `<div class="vtq-foot"><span>${u.synced ? `Checked with VirusTotal ${ago2(new Date(u.synced * 1000).toISOString())}` : "Counted by OmniShield"}${u.reserve ? ` · ${u.reserve} kept in reserve for your own checks` : ""}</span>
    <span class="sp"></span><button class="ghost sm" data-vt-sync>${IC("refresh")}Check usage</button></div>` : ""}`;
}
function wireSync(root) {
  root.querySelectorAll("[data-vt-sync]").forEach(b => b.onclick = async () => {
    b.disabled = true;
    try { await J("/api/vt/sync", {}); await refreshStatus(); say("Usage checked with VirusTotal (this doesn't use any lookups)", "refresh"); drawPage(true); if (pg() === "settings") drawVtSettings(); }
    catch (e) { say(e.message, "x"); } b.disabled = false;
  });
}

/* ================= VirusTotal page ================= */
async function loadVT() { await refreshStatus(); drawPage(); }
function drawPage(keep) {
  const s = VT.st, body = Q("#vtBody"); if (!s) return;
  Q("#vtHeadCost").innerHTML = s.configured ? `${IC("clock")}${n0(s.usage.day.left)} lookups left today` : "";
  if (!s.configured) {
    body.innerHTML = `<div class="card vt-setup"><div><h2 style="font-size:20px;font-weight:650">Connect your free VirusTotal account</h2>
      <p class="mute" style="margin-top:6px">VirusTotal checks files and links with more than 70 antivirus companies at once. A free account gives you 500 lookups a day - OmniShield makes sure you never go over.</p>
      <ol><li>Create a free account at <b>virustotal.com</b> and sign in.</li><li>Click your name (top right), then <b>API key</b>.</li><li>Copy the key and paste it in <b>Settings > VirusTotal</b>.</li></ol>
      <div class="vt-acts"><button class="btn" id="vtGoSet">${IC("key")}Add my API key</button><a class="ghost" href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener"><button class="ghost">${IC("ext")}Create a free account</button></a></div></div>
      <div class="callout info">${IC("info")}<div><b>What gets sent?</b> Files are identified only by their fingerprint (a SHA-256 code) - the file itself stays on your PC unless you choose to upload it. Links, websites and IP addresses you check are sent to VirusTotal.
      The free key is for personal, non-commercial use.</div></div></div>`;
    Q("#vtGoSet").onclick = () => openVtSettings();
    return;
  }
  const keepRes = keep && Q("#vtRes") ? Q("#vtRes").innerHTML : "";
  body.innerHTML = `<div class="d12">
    <div class="card c8"><div class="vt-tabs" id="vtTabs">${TABS.map(([k, i, l]) => `<button data-t="${k}" class="${VT.tab === k ? "on" : ""}">${IC(i)}${l}</button>`).join("")}</div>
      <div id="vtForm"></div><div id="vtRes">${keepRes}</div></div>
    <div class="card c4"><h3>Your lookups <span class="sub">${s.cfg.plan === "free" ? "Free key" : "Custom limits"}</span></h3><div id="vtQ">${meters(s.usage)}</div>
      <div class="callout info" style="margin-top:14px">${IC("info")}<div>Saved results are re-used for ${s.cfg.cache_days} day${s.cfg.cache_days > 1 ? "s" : ""} and don't use lookups. OmniShield never goes over your limits.</div></div></div>
    <div class="card c12"><div class="ua-sec-h"><h3>Recent checks</h3><span class="sub mute">Click one to see it again - free</span></div><div id="vtHist"><div class="skel"></div></div></div></div>`;
  QA("#vtTabs button").forEach(b => b.onclick = () => { VT.tab = b.dataset.t; QA("#vtTabs button").forEach(x => x.classList.toggle("on", x === b)); drawForm(); });
  wireSync(Q("#vtQ")); drawForm(); loadHistory();
}
function drawForm() {
  const f = Q("#vtForm"), c = VT.st.cfg, cost = (t = "Uses 1 lookup") => `<span class="vt-cost">${IC("clock")}${t}</span>`;
  const browse = `<button class="ghost" data-browse>${IC("folder")}Browse…</button>`;
  if (VT.tab === "file") f.innerHTML = `<div class="vt-form"><input type="text" id="vtIn" placeholder="A file on this PC, e.g. C:\\Users\\Ajay\\Downloads\\setup.exe">${browse}<button class="btn" data-go>${IC("search")}Check file</button></div>
    <div class="vt-drop" id="vtDrop">${IC("up")}<b>Or drop a file here</b>Your browser works out its fingerprint - the file itself isn't sent anywhere.</div>
    <div class="vt-help">${IC("info")}<span>Only the file's fingerprint (SHA-256) is sent to VirusTotal. ${cost()}</span></div>`;
  else if (VT.tab === "folder") f.innerHTML = `<div class="vt-form"><input type="text" id="vtIn" placeholder="A folder, e.g. C:\\Users\\Ajay\\Downloads\\NewTool">${browse}<button class="ghost" data-plan>${IC("info")}Estimate</button><button class="btn" data-go>${IC("search")}Check folder</button></div>
    <div class="vt-opts"><label><input type="checkbox" id="vtRisky" ${c.only_risky ? "checked" : ""}>Only programs, scripts, documents and archives</label>
      <label>Check up to <select id="vtMax">${[25, 50, 100, 250, 500].map(v => `<option ${v === c.folder_max ? "selected" : ""}>${v}</option>`).join("")}</select> files</label></div>
    <div id="vtPlan"></div>
    <div class="vt-help">${IC("info")}<span>Each new file uses 1 lookup; files you've checked before are free. With a free key that's 4 files a minute, so big folders take a while - you can leave this page.
      Stops automatically before eating into the ${c.reserve} lookups kept in reserve.</span></div>`;
  else if (VT.tab === "url") f.innerHTML = `<div class="vt-form"><input type="text" id="vtIn" placeholder="A link, e.g. https://example.com/login"><button class="btn" data-go>${IC("search")}Check link</button></div>
    <div class="vt-help">${IC("info")}<span>Paste a link from an email or message before you open it. The link is sent to VirusTotal. ${cost()}</span></div>`;
  else if (VT.tab === "site") f.innerHTML = `<div class="vt-form"><input type="text" id="vtIn" placeholder="A website or IP address, e.g. example.com or 185.220.101.7"><button class="btn" data-go>${IC("search")}Look up</button></div>
    <div class="vt-help">${IC("info")}<span>Handy for addresses you see on the Network or User activity pages. ${cost()}</span></div>`;
  else f.innerHTML = `<div class="vt-form"><input type="text" id="vtIn" class="vt-key-in" placeholder="MD5, SHA-1 or SHA-256 fingerprint"><button class="btn" data-go>${IC("search")}Look up</button></div>
    <div class="vt-help">${IC("info")}<span>Look up a fingerprint you got from a scan report or a colleague. ${cost()}</span></div>`;
  const inp = Q("#vtIn"); inp.onkeydown = e => { if (e.key === "Enter") go1(); };
  f.querySelector("[data-go]").onclick = go1;
  const br = f.querySelector("[data-browse]");
  if (br) br.onclick = async () => { if (!fn("pickPath")) return; const p = await pickPath({files: VT.tab === "file", title: VT.tab === "file" ? "Choose a file to check" : "Choose a folder to check", start: inp.value}); if (p) inp.value = p; };
  const pl = f.querySelector("[data-plan]"); if (pl) pl.onclick = estimate;
  const dz = Q("#vtDrop");
  if (dz) {
    const pick = document.createElement("input"); pick.type = "file"; pick.style.display = "none"; dz.append(pick);
    dz.onclick = e => { if (e.target === dz || e.target.closest("#vtDrop") && e.target !== pick) pick.click(); };
    pick.onchange = () => pick.files[0] && hashAndCheck(pick.files[0]);
    dz.ondragover = e => { e.preventDefault(); dz.classList.add("over"); };
    dz.ondragleave = () => dz.classList.remove("over");
    dz.ondrop = e => { e.preventDefault(); dz.classList.remove("over"); const fl = e.dataTransfer.files[0]; if (fl) hashAndCheck(fl); };
  }
}
async function hashAndCheck(file) {
  if (!crypto.subtle) { say("Your browser can't work out fingerprints here - use Browse instead.", "x"); return; }
  if (file.size > 1024 * 1048576) { say("That file is over 1 GB - use Browse instead.", "x"); return; }
  Q("#vtRes").innerHTML = `<div class="vt-wait"><div class="ua-spin"></div><span>Working out the fingerprint of <b>${E(file.name)}</b>…</span></div>`;
  const buf = await file.arrayBuffer(), h = [...new Uint8Array(await crypto.subtle.digest("SHA-256", buf))].map(b => b.toString(16).padStart(2, "0")).join("");
  doLookup({kind: "hash", value: h}, file.name);
}
function go1() {
  const v = Q("#vtIn").value.trim(); if (!v) { Q("#vtIn").focus(); return; }
  if (VT.tab === "folder") return startFolder(v);
  if (VT.tab === "site") return doLookup({kind: /^[\d.]+$|:/.test(v) && !/[a-z]{2,}\./i.test(v) ? "ip" : "domain", value: v});
  doLookup({kind: VT.tab === "file" ? "path" : VT.tab, value: v});
}
async function doLookup(req, label, force) {
  clearInterval(VT.retry); const res = Q("#vtRes");
  res.innerHTML = `<div class="vt-wait"><div class="ua-spin"></div><span>Asking VirusTotal…</span></div>`;
  try {
    const d = await J("/api/vt/lookup", {...req, force: !!force});
    if (label && !d.name) d.name = label;
    VT.last = {d, req, label}; showResult(d, req); refreshStatus().then(() => { if (Q("#vtQ")) { Q("#vtQ").innerHTML = meters(VT.st.usage); wireSync(Q("#vtQ")); } });
    loadHistory();
  } catch (e) {
    if (e.status === 429 && e.data && e.data.which === "minute") {
      let w = Math.ceil(e.data.wait || 15);
      const tick = () => { res.innerHTML = `<div class="vt-wait"><div class="ua-spin"></div><span>Your key allows ${VT.st.cfg.per_min} lookups a minute. Checking automatically in <b>${w} s</b>…</span><button class="ghost sm" style="margin-left:auto" id="vtCancelWait">Cancel</button></div>`;
        Q("#vtCancelWait").onclick = () => { clearInterval(VT.retry); res.innerHTML = ""; }; };
      tick(); VT.retry = setInterval(() => { if (--w <= 0) { clearInterval(VT.retry); doLookup(req, label, force); } else tick(); }, 1000);
      return;
    }
    res.innerHTML = `<div class="callout" style="margin-top:14px">${IC("alert")}<div>${E(e.message)}</div></div>`;
    if (e.status === 429) refreshStatus().then(() => drawPage(true));
  }
}
const VERD = {dangerous: ["alert", "Dangerous"], suspicious: ["alert", "Be careful"], clean: ["shield", "Looks safe"], unknown: ["q", "Not known"]};
function showResult(d, req) {
  const st = d.stats || {}, tot = d.engines || 0, kindName = {file: "File", url: "Link", domain: "Website", ip: "IP address"}[d.kind];
  const title = d.found === false ? {file: "VirusTotal has never seen this file", url: "VirusTotal hasn't checked this link yet", domain: "No information about this website", ip: "No information about this address"}[d.kind]
    : {dangerous: `${d.malicious} of ${tot} security companies flag this ${kindName.toLowerCase()}`, suspicious: `A few security companies flag this ${kindName.toLowerCase()}`,
       clean: `No security company flags this ${kindName.toLowerCase()}`, unknown: "Not analysed yet"}[d.verdict];
  const shown = d.path ? fname2(d.path) : d.name || d.label || d.key;
  const bar = tot ? `<div class="vt-stack">${[["m", st.malicious], ["s", st.suspicious], ["h", st.harmless], ["u", st.undetected]].map(([c, v]) => `<i class="${c}" style="width:${(v || 0) / tot * 100}%"></i>`).join("")}</div>
    <div class="vt-key"><span><i style="background:#ef4444"></i>Malicious ${st.malicious || 0}</span><span><i style="background:#f59e0b"></i>Suspicious ${st.suspicious || 0}</span>
    <span><i style="background:#10b981"></i>Harmless ${st.harmless || 0}</span><span><i style="background:var(--line2)"></i>No detection ${st.undetected || 0}</span></div>` : "";
  const kv = [["Name", d.name], ["Type", d.type], ["Size", d.size ? fsz(d.size) : d.size_local ? fsz(d.size_local) : ""], ["Threat name", d.threat], ["Page title", d.title],
    ["Category", (d.categories || []).join(", ")], ["Owner", d.owner], ["Country", d.country], ["Digitally signed", d.signed === undefined || d.signed === null ? "" : d.signed ? "Yes" : "No"],
    ["First seen", d.first_seen ? new Date(d.first_seen).toLocaleDateString() : ""], ["Last checked by VirusTotal", d.last_analysis ? ago2(d.last_analysis) : ""],
    ["Times submitted", d.times_submitted], ["Community score", d.reputation], ["SHA-256", d.kind === "file" ? (d.sha256 || d.key) : ""], ["On this PC", d.path || ""]].filter(x => x[1] !== undefined && x[1] !== null && x[1] !== "");
  const dets = d.detections || [];
  const canUpload = d.found === false && d.kind === "file" && d.path && d.can_upload;
  const acts = [`<a href="${E(d.link)}" target="_blank" rel="noopener"><button class="ghost">${IC("ext")}Full report on VirusTotal</button></a>`,
    d.cached ? `<button class="ghost" data-a="again">${IC("refresh")}Check again (1 lookup)</button>` : "",
    d.path && ["dangerous", "suspicious"].includes(d.verdict) && fn("quarantinePath") ? `<button class="danger" data-a="quar">${IC("lock")}Quarantine file</button>` : "",
    d.path && ["dangerous", "suspicious"].includes(d.verdict) && fn("blockDialog") ? `<button class="ghost" data-a="block">${IC("ban")}Block program</button>` : "",
    d.path && fn("startScan") ? `<button class="ghost" data-a="local">${IC("shield")}Also check with local antivirus</button>` : "",
    canUpload ? `<button class="btn" data-a="upload">${IC("up")}Upload for scanning</button>` : "",
    d.found === false && d.kind === "url" ? `<button class="btn" data-a="submit">${IC("up")}Ask VirusTotal to scan it (2-5 lookups)</button>` : ""].join("");
  Q("#vtRes").innerHTML = `<div class="vt-res"><div class="vt-v ${d.verdict}"><div class="big">${tot && d.found !== false ? `<div><b>${d.malicious}/${tot}</b><small>flagged</small></div>` : IC(VERD[d.verdict][0])}</div>
      <div style="min-width:0;position:relative;z-index:1"><h2>${E(title)}</h2><p>${E(d.what)}</p>
      <span class="tag2">${E(kindName)}: ${E(String(shown).length > 70 ? String(shown).slice(0, 67) + "…" : shown)}</span><span class="tag2">${d.cached ? "Saved result - no lookup used" : "Fresh result - used 1 lookup"}</span></div></div>
    ${bar}
    ${d.found === false && d.kind === "file" ? `<div class="callout info" style="margin-top:14px">${IC("info")}<div>${d.path ? (d.can_upload ? "You can upload it so VirusTotal scans it - but only do this for programs and downloads, <b>never</b> for private documents: uploaded files can be seen by security companies." : "Uploading is turned off (Settings > VirusTotal). Run the local check instead, or upload it yourself on virustotal.com.") : "Run 'Is this safe?' to check it with the local antivirus too."}</div></div>` : ""}
    <div class="vt-grid">${kv.length ? `<div><h3 style="font-size:14px;margin-bottom:10px">Details</h3><dl class="kv2">${kv.map(([k, v]) => `<dt>${E(k)}</dt><dd class="${k === "SHA-256" || k === "On this PC" ? "code" : ""}">${E(v)}</dd>`).join("")}</dl></div>` : "<div></div>"}
      ${dets.length ? `<div><h3 style="font-size:14px;margin-bottom:10px">What they call it <span class="sub mute">${dets.length} compan${dets.length > 1 ? "ies" : "y"}</span></h3>
        <table class="vt-det"><tr><th>Company</th><th>Detection</th></tr>${dets.slice(0, 12).map(x => `<tr><td>${E(x.engine)}</td><td class="r ${x.category === "suspicious" ? "s" : ""}">${E(x.result)}</td></tr>`).join("")}</table>
        ${dets.length > 12 ? `<p class="mute" style="font-size:12px;margin-top:6px">…and ${dets.length - 12} more in the full report.</p>` : ""}</div>` : ""}</div>
    <div class="vt-acts">${acts}</div></div>`;
  requestAnimationFrame(() => {});
  Q("#vtRes").querySelectorAll("[data-a]").forEach(b => b.onclick = async () => {
    const a = b.dataset.a;
    if (a === "again") doLookup(req || {kind: d.kind === "file" ? "hash" : d.kind, value: d.key}, null, true);
    else if (a === "quar") { if (await quarantinePath(d.path)) say("Quarantined", "lock"); }
    else if (a === "block") blockDialog(d.path);
    else if (a === "local") { goto("scan"); setTimeout(() => { fn("pickKind") && pickKind("check"); Q("#sPath") && (Q("#sPath").value = d.path); startScan(); }, 150); }
    else if (a === "upload") {
      const ok = fn("confirmBox") ? await confirmBox("Upload this file to VirusTotal?", `${d.path}\n\nUploaded files are shared with security companies and can be downloaded by VirusTotal's paying customers. Never upload private or work documents.`, "Upload", "btn") : confirm("Upload?");
      if (ok) runJob(J("/api/vt/upload", {path: d.path}), "Uploading and scanning");
    } else if (a === "submit") runJob(J("/api/vt/submit-url", {kind: "url", value: d.key}), "Scanning the link");
  });
}
async function runJob(p, label) {
  const res = Q("#vtRes");
  let j; try { j = (await p).job; } catch (e) { say(e.message, "x"); return; }
  res.innerHTML = `<div class="vt-wait"><div class="ua-spin"></div><span id="vtJobTxt">${E(label)}…</span></div>`;
  const t = setInterval(async () => {
    const x = await J("/api/jobs/" + j).catch(() => null); if (!x) return;
    if (x.state === "running") { const s = (x.progress || {}).step; if (s && Q("#vtJobTxt")) Q("#vtJobTxt").textContent = s; return; }
    clearInterval(t);
    if (x.state !== "done") { res.innerHTML = `<div class="callout" style="margin-top:14px">${IC("alert")}<div>${E((x.result || {}).error || "It didn't finish.")}</div></div>`; return; }
    const r = x.result.result; if (x.result.path) r.path = x.result.path;
    showResult(r, null); if (x.result.pending) say("VirusTotal is still working on it - check again in a few minutes.", "clock");
    refreshStatus(); loadHistory();
  }, 2000);
}
async function estimate() {
  const v = Q("#vtIn").value.trim(); if (!v) { Q("#vtIn").focus(); return; }
  try {
    const p = await J("/api/vt/plan", {path: v, only_risky: Q("#vtRisky").checked, max_files: +Q("#vtMax").value});
    Q("#vtPlan").innerHTML = `<div class="vt-plan"><div><b>${n0(p.files)}</b><span>files to check</span></div><div><b>${n0(p.lookups_max)}</b><span>lookups at most</span></div>
      <div><b>${p.minutes < 1 ? "<1" : "~" + Math.ceil(p.minutes)} min</b><span>at ${p.per_min} a minute</span></div><div><b>${n0(Math.max(0, p.usage.day.left - p.lookups_max))}</b><span>left today afterwards</span></div></div>
      ${p.files > p.lookups_max ? `<div class="callout" style="margin-top:10px">${IC("info")}<div>${n0(p.files - p.lookups_max)} file${p.files - p.lookups_max > 1 ? "s" : ""} won't be checked (limit or today's budget). Files you've checked before are free, so the real number is often lower.</div></div>` : ""}`;
  } catch (e) { say(e.message, "x"); }
}
async function startFolder(path) {
  let j; try { j = (await J("/api/vt/folder", {path, only_risky: Q("#vtRisky").checked, max_files: +Q("#vtMax").value})).job; } catch (e) { say(e.message, "x"); return; }
  VT.job = j; trackFolder(j);
}
function trackFolder(j) {
  const res = Q("#vtRes"); if (!res) return;
  res.innerHTML = `<div class="vt-res"><div class="vt-wait" style="flex-wrap:wrap"><div class="ua-spin"></div><span id="vtFt">Starting…</span><button class="ghost sm" style="margin-left:auto" id="vtStop">${IC("stop")}Stop</button>
    <div class="progress det" style="width:100%;margin:6px 0 0"><div id="vtFb" style="width:2%"></div></div></div></div>`;
  Q("#vtStop").onclick = () => fetch(`/api/jobs/${j}/cancel`, {method: "POST"});
  const t = setInterval(async () => {
    const x = await J("/api/jobs/" + j).catch(() => null); if (!x) return;
    if (x.state === "running") {
      const p = x.progress || {}, el = Q("#vtFt"); if (!el) { clearInterval(t); return; }
      if (p.phase === "vt_hash") el.innerHTML = `Working out fingerprints… <b>${n0(p.vt_done)}</b> of ${n0(p.vt_total)} files`;
      else if (p.phase === "virustotal") {
        const left = p.vt_total - p.vt_done, mins = Math.ceil(left / Math.max(1, VT.st.cfg.per_min));
        el.innerHTML = `Asking VirusTotal… <b>${n0(p.vt_done)}</b> of ${n0(p.vt_total)}${left > 0 ? ` · about ${mins} min left` : ""}${p.wait > 1 ? ` · waiting ${Math.ceil(p.wait)} s for the per-minute limit` : ""}<br><span class="mute" style="font-size:12px">${E(fname2(p.current || ""))}</span>`;
        Q("#vtFb").style.width = Math.max(2, p.vt_done / Math.max(1, p.vt_total) * 100) + "%";
      }
      if (Math.random() < .3) refreshStatus();
      return;
    }
    clearInterval(t); VT.job = null; refreshStatus(); loadHistory();
    if (x.state === "error") { res.innerHTML = `<div class="callout" style="margin-top:14px">${IC("alert")}<div>${E((x.result || {}).error)}</div></div>`; return; }
    showFolder(x.result);
  }, 1500);
}
function showFolder(r) {
  const fl = r.flagged || [], v = fl.some(f => f.verdict === "dangerous") ? "dangerous" : fl.length ? "suspicious" : r.checked ? "clean" : "unknown";
  const title = v === "dangerous" ? `${fl.length} file${fl.length > 1 ? "s" : ""} flagged as dangerous` : v === "suspicious" ? `${fl.length} file${fl.length > 1 ? "s" : ""} need a closer look` : v === "clean" ? "Nothing flagged by VirusTotal" : "No files were checked";
  Q("#vtRes").innerHTML = `<div class="vt-res"><div class="vt-v ${v}"><div class="big">${IC(v === "clean" ? "shield" : "alert")}</div><div style="position:relative;z-index:1"><h2>${title}</h2>
      <p>${n0(r.checked)} file${r.checked === 1 ? "" : "s"} checked in ${E(fname2(r.path) || r.path)} · ${n0(r.lookups)} lookup${r.lookups === 1 ? "" : "s"} used, ${n0(r.cached)} from saved results · ${n0(r.unknown)} unknown to VirusTotal</p>
      ${r.cancelled ? '<span class="tag2">Stopped early</span>' : ""}${r.skipped_limit ? `<span class="tag2">${n0(r.skipped_limit)} not checked (limit)</span>` : ""}</div></div>
    ${r.stopped && r.stopped !== "cancel" ? `<div class="callout" style="margin-top:12px">${IC("info")}<div>${E(r.stopped)}</div></div>` : ""}
    ${fl.length ? `<div class="mt">${fl.map((f, i) => `<div class="finding"><div class="top"><div class="ic ${f.verdict === "dangerous" ? "sev-high" : "sev-medium"}">${IC("alert")}</div>
      <div style="flex:1;min-width:0"><div class="nm">${E(fname2(f.path))}</div><div class="pt">${E(f.path)}</div></div><span class="vt-pill ${f.verdict}">${f.malicious}/${f.engines}</span></div>
      <div class="reason ${f.verdict === "dangerous" ? "dangerous" : "suspicious"}"><span class="lbl">What's wrong</span>${E(f.what)}</div>
      <div class="acts"><a href="${E(f.link)}" target="_blank" rel="noopener"><button class="ghost sm">${IC("ext")}Full report</button></a>
        ${fn("quarantinePath") ? `<button class="danger sm" data-q="${i}">${IC("lock")}Quarantine</button>` : ""}${fn("blockDialog") ? `<button class="ghost sm" data-b="${i}">${IC("ban")}Block</button>` : ""}</div></div>`).join("")}</div>` : ""}
    ${(r.items || []).length ? `<details class="mt"><summary>All ${n0(r.items.length)} files</summary><div class="vt-items"><div class="vt-hist">${r.items.map(it => `<div class="vt-hi" data-h="${it.sha256}"><div class="k">${IC("file")}</div><div class="t"><b>${E(fname2(it.path))}</b><span>${E(it.path)}</span></div>
      <span class="vt-pill ${it.verdict}">${it.verdict === "unknown" ? "Not known" : it.engines ? it.malicious + "/" + it.engines : it.verdict}</span></div>`).join("")}</div></div></details>` : ""}</div>`;
  Q("#vtRes").querySelectorAll("[data-q]").forEach(b => b.onclick = async () => { if (await quarantinePath(fl[+b.dataset.q].path)) b.disabled = true; });
  Q("#vtRes").querySelectorAll("[data-b]").forEach(b => b.onclick = () => blockDialog(fl[+b.dataset.b].path));
  Q("#vtRes").querySelectorAll("[data-h]").forEach(x => x.onclick = () => openSaved("file", x.dataset.h));
}
async function loadHistory() {
  const el = Q("#vtHist"); if (!el) return;
  let h; try { h = await J("/api/vt/history?limit=40"); } catch { return; }
  const ico = {file: "file", url: "link", domain: "globe", ip: "globe"};
  const all = h.length, shown = VT.histAll ? h : h.slice(0, 8);
  el.innerHTML = h.length ? `<div class="vt-hist">${shown.map(x => `<div class="vt-hi" data-k="${x.kind}" data-key="${E(x.key)}"><div class="k">${IC(ico[x.kind])}</div>
    <div class="t"><b>${E(x.label && x.label !== x.key ? x.label : x.kind === "file" ? "File " + x.key.slice(0, 12) + "…" : x.key)}</b><span>${E(x.kind === "file" ? x.key : x.kind)} · ${ago2(x.time)}</span></div>
    <span class="vt-pill ${x.verdict}">${x.found === false ? "Not known" : x.verdict === "clean" ? "Safe" : x.verdict === "unknown" ? "Not analysed" : `${x.malicious}/${x.engines}`}</span></div>`).join("")}</div>
    ${all > 8 ? `<div class="ua-more" style="margin-top:8px"><button class="ghost sm" id="vtHistMore">${VT.histAll ? "Show fewer" : `Show all ${all}`}</button></div>` : ""}`
    : `<p class="mute">Nothing checked yet. Results you look up appear here and can be opened again without using a lookup.</p>`;
  el.querySelectorAll("[data-k]").forEach(x => x.onclick = () => openSaved(x.dataset.k, x.dataset.key));
  const m = Q("#vtHistMore"); if (m) m.onclick = () => { VT.histAll = !VT.histAll; loadHistory(); };
}
async function openSaved(kind, key) {
  try { const d = await J(`/api/vt/result?kind=${kind}&key=${encodeURIComponent(key)}`); showResult(d, {kind: kind === "file" ? "hash" : kind, value: key}); Q("#vtRes").scrollIntoView({behavior: "smooth", block: "start"}); }
  catch (e) { say(e.message, "x"); }
}

/* ================= Settings > VirusTotal ================= */
function openVtSettings() { goto("settings"); setTimeout(() => { try { setTabName = "vt"; } catch {} if (fn("drawSettings")) drawSettings(); }, 100); }
const setNav = Q("#setNav");
if (setNav && !setNav.querySelector('[data-t="vt"]')) {
  const a = document.createElement("a"); a.dataset.t = "vt"; a.innerHTML = IC("vtnav") + "VirusTotal";
  a.onclick = () => { try { setTabName = "vt"; } catch {} if (fn("drawSettings")) drawSettings(); };
  const before = setNav.querySelector('[data-t="maint"]'); before ? setNav.insertBefore(a, before) : setNav.append(a);
}
const _drawSettings = fn("drawSettings");
if (_drawSettings) window.drawSettings = async function () {
  const r = await _drawSettings.apply(this, arguments);
  let t = ""; try { t = setTabName; } catch {}
  QA("#setNav a").forEach(a => a.classList.toggle("on", a.dataset.t === t));
  if (t === "vt") await drawVtSettings();
  return r;
};
async function drawVtSettings() {
  const b = Q("#setBody"); if (!b) return;
  const s = await refreshStatus(); if (!s) return;
  const c = s.cfg, row = (t, h, ctl) => `<div class="srow"><div class="lbl"><b>${t}</b>${h ? `<span>${h}</span>` : ""}</div><div class="ctl">${ctl}</div></div>`;
  const tog = (on, k) => `<label class="switch sm"><input type="checkbox" ${on ? "checked" : ""} data-vk="${k}"><i></i></label>`;
  const sel = (cur, opts, k) => `<select data-vk="${k}">${opts.map(([v, l]) => `<option value="${v}" ${String(cur) === String(v) ? "selected" : ""}>${l}</option>`).join("")}</select>`;
  b.innerHTML = `<div class="set-sec card"><h2>${IC("vtnav")}VirusTotal</h2><p>Check files and links with 70+ security companies. OmniShield keeps track of every lookup and never goes over your limits.</p>
    ${row("API key", s.configured ? `Connected · ${E(s.key)}` : "Find it on virustotal.com: click your name, then API key.",
      s.configured ? `<button class="ghost sm" id="vtTest">${IC("check")}Test</button><button class="ghost sm" id="vtChange">${IC("key")}Change</button><button class="ghost sm" id="vtRemove">${IC("trash")}Remove</button>`
                   : `<input type="password" id="vtKey" class="vt-key-in" placeholder="Paste your 64-character key" style="width:320px" autocomplete="off"><button class="btn sm" id="vtSave">Save</button>`)}
    <div id="vtKeyEdit" class="hide" style="padding:0 0 14px"><div class="vt-form"><input type="password" id="vtKey2" class="vt-key-in" placeholder="Paste the new key" autocomplete="off"><button class="btn sm" id="vtSave2">Save new key</button></div></div>
    </div>
    <div class="set-sec card"><h2>${IC("clock")}Lookup limits</h2><p>OmniShield reserves each lookup before sending it, so it never goes over.</p>
    ${row("Your plan", "The free key allows 4 lookups a minute, 500 a day and 15,500 a month.", `<div class="seg" id="vtPlan">${[["free", "Free key"], ["custom", "Custom"]].map(([v, l]) => `<button data-v="${v}" class="${c.plan === v ? "on" : ""}">${l}</button>`).join("")}</div>`)}
    ${c.plan === "custom" ? row("Custom limits", "From your VirusTotal plan.", `<input type="number" min="1" value="${c.per_min}" data-vn="per_min" style="width:90px" title="per minute"> / min
      <input type="number" min="1" value="${c.per_day}" data-vn="per_day" style="width:110px" title="per day"> / day <input type="number" min="1" value="${c.per_month}" data-vn="per_month" style="width:120px" title="per month"> / month`) : ""}
    ${row("Keep in reserve", "Folder checks and safety checks stop early so you always have some lookups left for checking things yourself.", sel(c.reserve, [[0, "None"], [10, "10 lookups"], [25, "25 lookups"], [50, "50 lookups"], [100, "100 lookups"]], "reserve"))}
    ${row("Re-use saved results for", "Saved results don't use lookups. Files that weren't known are re-checked after a day.", sel(c.cache_days, [[1, "1 day"], [7, "7 days"], [30, "30 days"]], "cache_days"))}
    ${s.configured ? `<div style="padding-top:14px" id="vtSetQ">${meters(s.usage)}</div>` : ""}</div>
    <div class="set-sec card"><h2>${IC("shield")}"Is this safe?" and scans</h2><p>How VirusTotal is used when you check a file or folder.</p>
    ${row("Ask VirusTotal first in \"Is this safe?\"", "VirusTotal checks the files first, then the local antivirus and pattern rules run as usual.", tog(c.use_in_check, "use_in_check"))}
    ${row("Files per safety check", "Programs and scripts are checked first. The rest are checked locally only.", sel(c.check_max, [[5, "5 files"], [10, "10 files"], [20, "20 files"], [50, "50 files"], [100, "100 files"]], "check_max"))}
    ${row("Only check risky file types", "Programs, scripts, documents and archives - skips photos, music and videos.", tog(c.only_risky, "only_risky"))}
    ${row("Files VirusTotal has never seen", "Uploading lets VirusTotal scan them, but uploaded files are shared with security companies. Never upload private documents.",
      `<div class="seg" id="vtUp">${[["never", "Never upload"], ["ask", "Let me choose"]].map(([v, l]) => `<button data-v="${v}" class="${c.upload === v ? "on" : ""}">${l}</button>`).join("")}</div>`)}</div>
    <div class="callout info">${IC("info")}<div>${E(s.privacy)} The free key is for personal, non-commercial use.</div></div>`;
  const save = async (body, msg) => { try { VT.st = await J("/api/vt/settings", body); drawSide(); if (fn("flashSaved")) flashSaved(); if (msg) say(msg); drawVtSettings(); } catch (e) { say(e.message, "x"); } };
  const sv = Q("#vtSave"); if (sv) sv.onclick = () => { const k = Q("#vtKey").value.trim(); if (k) save({api_key: k}, "API key saved").then(() => testKey()); };
  const ch = Q("#vtChange"); if (ch) ch.onclick = () => Q("#vtKeyEdit").classList.toggle("hide");
  const sv2 = Q("#vtSave2"); if (sv2) sv2.onclick = () => { const k = Q("#vtKey2").value.trim(); if (k) save({api_key: k}, "API key changed").then(() => testKey()); };
  const rm = Q("#vtRemove"); if (rm) rm.onclick = async () => { if (!fn("confirmBox") || await confirmBox("Remove the VirusTotal key?", "VirusTotal won't be used until you add a key again. Saved results are kept.", "Remove")) save({remove_key: true}, "API key removed"); };
  const ts = Q("#vtTest"); if (ts) ts.onclick = testKey;
  QA("#vtPlan button").forEach(x => x.onclick = () => save({plan: x.dataset.v}));
  QA("#vtUp button").forEach(x => x.onclick = () => save({upload: x.dataset.v}));
  QA("[data-vk]").forEach(el => el.onchange = () => save({[el.dataset.vk]: el.type === "checkbox" ? el.checked : +el.value}));
  QA("[data-vn]").forEach(el => el.onchange = () => save({[el.dataset.vn]: +el.value}));
  const q = Q("#vtSetQ"); if (q) wireSync(q);
}
async function testKey() {
  try { const r = await fetch("/api/vt/test", {method: "POST"}); const j = await r.json(); if (!r.ok) throw new Error(j.detail); say(j.message, "check"); await refreshStatus(); if (pg() === "settings") drawVtSettings(); }
  catch (e) { say(e.message, "x"); }
}

/* ================= "Is this safe?" integration ================= */
const note = Q("#checkNote > div");
const setNote = () => { if (note && VT.st) note.innerHTML = VT.st.configured && VT.st.cfg.use_in_check
  ? `<b>Read-only safety check.</b> VirusTotal checks the files first (up to ${VT.st.cfg.check_max}, using their fingerprints), then your local antivirus and pattern rules check everything. Exclusions are ignored. Nothing is moved, changed or deleted.`
  : `<b>Read-only safety check.</b> Everything you pick is checked, <b>even folders and file types in your exclusions</b>. Nothing is moved, changed or deleted - you just get the results.`; };
const _draw = fn("drawProgress");
if (_draw) window.drawProgress = function (p) {
  if (p && (p.phase === "virustotal" || p.phase === "vt_hash")) {
    const bar = Q("#runBar"), det = p.phase === "virustotal" && p.vt_total;
    if (bar) { bar.classList.toggle("det", !!det); bar.firstElementChild.style.width = det ? Math.max(2, p.vt_done / p.vt_total * 100) + "%" : ""; }
    const t = Q("#runTitle"); if (t) t.textContent = p.phase === "vt_hash" ? "Step 1 of 2 · Preparing files for VirusTotal…" : "Step 1 of 2 · Asking VirusTotal…";
    const ph = Q("#runPhase"); if (ph) ph.textContent = p.phase === "vt_hash" ? `${n0(p.vt_done)} of ${n0(p.vt_total)} files` :
      `${n0(p.vt_done)} of ${n0(p.vt_total)} files${p.wait > 1 ? ` · waiting ${Math.ceil(p.wait)} s (your key allows ${VT.st ? VT.st.cfg.per_min : 4} a minute)` : ""}`;
    const pc = Q("#runPct"); if (pc) pc.textContent = det ? Math.floor(p.vt_done / p.vt_total * 100) + "%" : "";
    const cu = Q("#runCur"); if (cu) cu.textContent = p.current || "";
    return;
  }
  const r = _draw.apply(this, arguments);
  if (p && ["counting", "scanning", "antivirus"].includes(p.phase) && VT.st && VT.st.configured && VT.st.cfg.use_in_check) {
    const t = Q("#runTitle"); if (t && !/^Step/.test(t.textContent) && Q("#runWhat") && /Safety check/.test(Q("#runWhat").textContent)) t.textContent = "Step 2 of 2 · " + t.textContent;
  }
  return r;
};
const _show = fn("showReport");
if (_show) window.showReport = function (j) {
  const r = _show.apply(this, arguments);
  const vt = j && j.result && j.result.vt, d = Q("#scanDone");
  if (vt && d) {
    const parts = [`${n0(vt.checked)} file${vt.checked === 1 ? "" : "s"} checked`, vt.flagged ? `<b class="bad-t">${vt.flagged} flagged</b>` : "none flagged",
      vt.unknown ? `${vt.unknown} not known to VirusTotal` : "", vt.lookups ? `${vt.lookups} lookup${vt.lookups > 1 ? "s" : ""} used` : "", vt.cached ? `${vt.cached} from saved results` : "",
      vt.skipped ? `${vt.skipped} checked locally only` : ""].filter(Boolean).join(" · ");
    const box = document.createElement("div"); box.className = "vt-scanbox";
    box.innerHTML = `<h4>${IC("vt")}VirusTotal (step 1)</h4><div style="font-size:13.5px;color:var(--text2)">${parts}</div>
      ${vt.usage ? `<div class="mute" style="font-size:12px;margin-top:6px">${n0(vt.usage.day.left)} lookups left today</div>` : ""}`;
    const hero = d.querySelector(".hero"); hero ? hero.after(box) : d.prepend(box);
    refreshStatus();
  }
  return r;
};

/* ---- page hook ---- */
const _load = fn("load");
window.load = function () { if (pg() === "vt") return loadVT(); if (pg() === "scan") refreshStatus().then(setNote); return _load && _load.apply(this, arguments); };
refreshStatus().then(setNote);
setInterval(() => { if (!document.hidden) refreshStatus().then(() => { if (pg() === "vt" && Q("#vtQ")) { Q("#vtQ").innerHTML = meters(VT.st.usage); wireSync(Q("#vtQ")); Q("#vtHeadCost").innerHTML = `${IC("clock")}${n0(VT.st.usage.day.left)} lookups left today`; } }); }, 20000);
})();
