/* Security Console add-on 1.8
   - User activity: who signs in, how, and anything unusual (per person)
   - Security checkup: Windows + Security Console settings with one-click fixes
   - Getting started checklist on the Dashboard
   - Printable reports (Print / Save as PDF)
   Works on top of Security Console 1.7. Nothing here changes settings by itself. */
(function () {
"use strict";
const Q = s => document.querySelector(s), QA = s => [...document.querySelectorAll(s)];
const E = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fn = n => typeof window[n] === "function" ? window[n] : null;
const GET = async u => { const r = await fetch(u, {cache: "no-store"}); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.detail || r.statusText); return j; };
const pg = () => { try { return page; } catch { return ""; } };          // "page" is Security Console's current page
const say = (m, k = "check") => fn("toast") ? toast(m, k) : console.log(m);
const goto = p => fn("go") && go(p);
const LS = k => localStorage.getItem(k) === "1";
const EMPTY = (t, s) => `<div class="empty"><b>${t}</b>${s ? "<br>" + s : ""}</div>`;

/* ---- icons (added to Security Console's icon set) ---- */
const MY = {
  users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
  clip: '<rect x="8" y="2" width="8" height="4" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="m9 14 2 2 4-4"/>',
  print: '<path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  remote: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4M8 10h8M13 7l3 3-3 3"/>',
  login: '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3"/>',
  ext: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5"/>', star: '<path d="m12 2 3.1 6.3 6.9 1-5 4.8 1.2 6.9L12 17.8 5.8 21 7 14.1 2 9.3l6.9-1z"/>',
  chev: '<path d="m6 9 6 6 6-6"/>', check: '<path d="M20 6 9 17l-5-5"/>', x: '<path d="M18 6 6 18M6 6l12 12"/>',
  alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v4h1"/>', shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  play: '<polygon points="6 3 20 12 6 21 6 3"/>', clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'};
try { if (typeof I === "object") for (const k in MY) if (!I[k]) I[k] = MY[k]; } catch {}
const IC = (n, a = "") => `<svg viewBox="0 0 24 24" ${a}>${(typeof I === "object" && I[n]) || MY[n] || MY.info}</svg>`;
const ago2 = t => fn("ago") ? ago(t) : new Date(t).toLocaleString();
const num2 = n => Number(n || 0).toLocaleString();
const AVC = ["#6366f1","#8b5cf6","#06b6d4","#10b981","#f59e0b","#ec4899","#0ea5e9","#14b8a6"];
const avc = t => { if (fn("avColor")) return avColor(t); let h = 0; for (const c of String(t)) h = (h * 31 + c.charCodeAt(0)) >>> 0; return AVC[h % AVC.length]; };
const initial = n => (String(n).split("\\").pop().replace(/[^a-z0-9]/i, "").charAt(0) || "?").toUpperCase();
const shortName = u => u.unknown ? "Unknown account names" : String(u.display).split("\\").pop();
const fmtWhen = t => { const d = new Date(t); return d.toLocaleDateString(undefined, {weekday: "short", day: "numeric", month: "short"}) + ", " + d.toLocaleTimeString([], {hour: "numeric", minute: "2-digit"}); };
const hr = h => { h %= 24; return h === 0 ? "12a" : h < 12 ? h + "a" : h === 12 ? "12p" : (h - 12) + "p"; };
const DAYS = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
const SEVI = {critical: "alert", high: "alert", medium: "info", low: "clock"};
const SEVL = {critical: "Serious", high: "High", medium: "Check", low: "Info"};

/* ================= register pages, nav and labels ================= */
try {
  PAGES.users = ["User activity", "Who signs in, how, and anything unusual"];
  PAGES.checkup = ["Security checkup", "The settings that keep your PC safe"];
} catch {}
try { if (typeof SRC === "object") SRC.users = ["User activity", "users"]; } catch {}
try { if (typeof ENG_COLOR === "object") ENG_COLOR.users = "#ec4899"; } catch {}
const fEng = Q("#fEng");
if (fEng && !fEng.querySelector('option[value="users"]')) fEng.insertAdjacentHTML("beforeend", '<option value="users">User activity</option>');

function navLink(p, label, icon) {
  const a = document.createElement("a"); a.dataset.p = p;
  a.innerHTML = IC(icon) + `<span class="lbl">${label}</span><span class="badge hide" id="nb-${p}"></span>`;
  a.onclick = () => goto(p); return a;
}
const after = Q('.nav a[data-p="check"]') || Q('.nav a[data-p="net"]') || Q('.nav a[data-p="system"]');
const navU = navLink("users", "User activity", "users"), navC = navLink("checkup", "Security checkup", "clip");
if (after) { after.after(navU); navU.after(navC); } else { const n = Q(".nav"); n && n.append(navU, navC); }
if (fn("moveInd")) requestAnimationFrame(moveInd);

const main = Q("main");
main.insertAdjacentHTML("beforeend", `
<section id="p-users" class="hide">
  <div class="ua-printhead"><div><b>User activity report</b><br><span id="uaPH"></span></div><span>Security Console</span></div>
  <div class="head"><div><h1>User activity</h1><p>Who signs in to this PC, how they sign in, and anything unusual - in plain English.</p></div>
    <div class="ua-tools no-print"><span class="ua-upd hide" id="uaUpd"><i></i>Updating…</span>
      <div class="seg" id="uaDays"><button data-v="1">24 hours</button><button data-v="7">7 days</button><button data-v="14" class="on">14 days</button><button data-v="30">30 days</button></div>
      <button class="ghost" id="uaRefresh">${IC("refresh")}Refresh</button><button class="ghost" id="uaPrint">${IC("print")}Print report</button></div></div>
  <div id="uaBody"></div>
</section>
<section id="p-checkup" class="hide">
  <div class="ua-printhead"><div><b>Security checkup</b><br><span id="ckPH"></span></div><span>Security Console</span></div>
  <div class="head"><div><h1>Security checkup</h1><p>A quick look at the settings that keep your PC safe. Fix anything amber or red with one click.</p></div>
    <div class="ua-tools no-print"><button class="ghost" id="ckRun">${IC("refresh")}Check again</button><button class="ghost" id="ckPrint">${IC("print")}Print</button></div></div>
  <div id="ckBody"></div>
</section>`);

/* ---- hook into Security Console's page loader ---- */
const _load = fn("load");
window.load = function () {
  const p = pg();
  if (p === "users") { localStorage.setItem("ua_users_seen", "1"); return loadUsers(); }
  if (p === "checkup") { localStorage.setItem("ua_checkup_seen", "1"); return loadCheckup(); }
  return _load && _load.apply(this, arguments);
};
const _home = fn("loadHome");
if (_home) window.loadHome = async function () { const r = await _home.apply(this, arguments); homeExtras().catch(() => {}); return r; };
const _hunt = fn("hunt");
if (_hunt) window.hunt = function (id) { if (id === "startup_items") localStorage.setItem("ua_startup_seen", "1"); return _hunt.apply(this, arguments); };

/* ================= shared renderers ================= */
function heat(h, odd = [], big = true) {
  const max = Math.max(1, ...h.flat()), oddS = new Set(odd.map(([d, x]) => d + "-" + x));
  const head = big ? `<span></span>${Array.from({length: 24}, (_, i) => `<span class="ua-hl">${i % 3 === 0 ? hr(i) : ""}</span>`).join("")}` : "";
  return `<div class="ua-heat ${big ? "big" : "mini"}">${head}${h.map((row, d) => (big ? `<span class="ua-dl">${DAYS[d]}</span>` : "") +
    row.map((v, x) => `<i class="${v ? "" : "z"} ${oddS.has(d + "-" + x) ? "odd" : ""}" style="--a:${v ? (.2 + .8 * v / max).toFixed(2) : 0}" title="${DAYS[d]} ${hr(x)}-${hr(x + 1)}: ${v} sign-in${v === 1 ? "" : "s"}"></i>`).join("")).join("")}</div>`;
}
const legend = () => `<div class="ua-legend"><span>Fewer<span class="scale">${[.2, .45, .7, 1].map(a => `<i style="background:color-mix(in srgb,var(--brand) ${a * 100}%,var(--surface2))"></i>`).join("")}</span>More sign-ins</span><span><span class="oddk"></span>Unusual time</span></div>`;
function bars(obj, cls = "") {
  const e = Object.entries(obj || {}); if (!e.length) return `<p class="mute">Nothing recorded.</p>`;
  const max = Math.max(...e.map(x => x[1]));
  return `<div class="ua-bars">${e.map(([k, v]) => `<div class="ua-bar ${cls}"><div class="ua-bt"><span>${E(k)}</span><b>${num2(v)}</b></div><div class="tr"><i style="width:0" data-w="${v / max * 100}%"></i></div></div>`).join("")}</div>`;
}
const animateBars = root => requestAnimationFrame(() => requestAnimationFrame(() => root.querySelectorAll("[data-w]").forEach(b => b.style.width = b.dataset.w)));
function findingRow(f, i, showUser) {
  return `<div class="ua-f sev-${f.sev}" data-i="${i}"><div class="ua-fh"><div class="ua-ficon">${IC(SEVI[f.sev])}</div>
    <div class="ua-ft"><span class="ua-sevtag">${SEVL[f.sev]}</span><b>${E(f.title)}</b>${showUser ? `<span class="ua-chip" data-user="${E(f.user)}">${IC("users", 'style="width:12px;height:12px"')}${E(String(f.user_name).split("\\").pop())}</span>` : ""}
      <p>${E(f.what)}</p></div><span class="ua-when">${f.when ? ago2(f.when) : ""}</span>${IC("chev", 'class="ua-chev"')}</div>
    <div class="ua-fb"><div class="ua-cols"><div><h5>What to do</h5><ol class="steps">${f.steps.map(s => `<li>${E(s)}</li>`).join("")}</ol></div>
      <div><h5>Could it be normal?</h5><p>${E(f.fp)}</p></div></div></div></div>`;
}
function wireFindings(root, list) {
  root.addEventListener("click", e => {
    const chip = e.target.closest(".ua-chip"); if (chip) { e.stopPropagation(); openPerson(chip.dataset.user); return; }
    const h = e.target.closest(".ua-fh"); if (h) h.parentElement.classList.toggle("open");
  });
}

/* ================= USER ACTIVITY page ================= */
let UA = {days: 14, data: null, timer: null, showAll: false};
QA("#uaDays button").forEach(b => b.onclick = () => { QA("#uaDays button").forEach(x => x.classList.toggle("on", x === b)); UA.days = +b.dataset.v; UA.data = null; loadUsers(); });
Q("#uaRefresh").onclick = () => loadUsers(true);
Q("#uaPrint").onclick = () => {
  if (!UA.data) return;
  const was = UA.showAll; UA.showAll = true; drawUsers();
  QA("#uaBody .ua-f").forEach(f => f.classList.add("open"));
  setTimeout(() => { window.print(); UA.showAll = was; drawUsers(); }, 150);
};

async function loadUsers(refresh) {
  clearTimeout(UA.timer);
  let r;
  try { r = await GET(`/api/users/report?days=${UA.days}${refresh ? "&refresh=true" : ""}`); }
  catch (e) { Q("#uaBody").innerHTML = `<div class="card">${EMPTY("Couldn't load user activity", E(e.message))}</div>`; return; }
  Q("#uaUpd").classList.toggle("hide", r.status !== "building" || !r.data);
  if (r.status === "building" && pg() === "users") UA.timer = setTimeout(() => loadUsers(), 2000);
  if (r.error && !r.data) { Q("#uaBody").innerHTML = `<div class="callout">${IC("alert")}<div>${E(r.error)}</div></div>`; return; }
  if (!r.data) {
    Q("#uaBody").innerHTML = `<div class="card"><div class="ua-loading"><div class="ua-spin"></div><b>Reading Windows sign-in records…</b>
      <span>This takes a few seconds the first time. Security Console looks at sign-ins, wrong passwords, account changes and the programs each person runs.</span></div></div>`;
    return;
  }
  if (r.data === UA.data) return;
  UA.data = r.data; drawUsers();
}

function drawUsers() {
  const d = UA.data, s = d.summary, real = d.users.filter(u => !u.unknown);
  Q("#uaPH").textContent = `Last ${d.days === 1 ? "24 hours" : d.days + " days"} · created ${new Date(d.generated).toLocaleString()}`;
  const methods = {}, fails = {};
  d.users.forEach(u => { for (const k in u.methods) methods[k] = (methods[k] || 0) + u.methods[k]; for (const k in u.fail_reasons) fails[k] = (fails[k] || 0) + u.fail_reasons[k]; });
  const F = d.findings, serious = F.filter(f => f.sev === "critical" || f.sev === "high").length;
  const shown = UA.showAll ? F : F.slice(0, 6);
  const tile = (icon, bg, val, lbl, sub) => `<div class="card kpi c3"><div class="ic" style="${bg}">${IC(icon)}</div><div><b>${val}</b><span>${lbl}</span>${sub ? `<div class="mute" style="font-size:12px">${sub}</div>` : ""}</div></div>`;
  Q("#uaBody").innerHTML = `
    ${d.notes.map(n => `<div class="callout ua-note">${IC("info")}<div>${E(n)}</div></div>`).join("")}
    <div class="d12 stagger">
      ${tile("users", "background:var(--brandSoft);color:var(--brand)", num2(s.people), "People using this PC", `${num2(s.signins)} sign-ins`)}
      ${tile("alert", "", num2(s.attention), "Need your attention", s.unusual ? `${s.unusual} with something unusual` : "").replace('class="ic"', `class="ic ${s.attention ? "sev-high" : ""}" `)}
      ${tile("key", "", num2(s.failed), "Wrong passwords", "Failed sign-in attempts").replace('class="ic"', `class="ic ${s.failed ? "sev-medium" : ""}" `)}
      ${tile("remote", "background:var(--surface2);color:var(--text2)", num2(s.remote), "Remote sign-ins", s.odd_hours ? `${s.odd_hours} at unusual times` : "Remote Desktop")}

      <div class="card c12"><div class="ua-sec-h"><h3>${serious ? IC("alert", 'style="color:var(--bad);vertical-align:-3px"') + " " : ""}What we noticed</h3>
        <span class="sub mute">${F.length ? `${F.length} finding${F.length > 1 ? "s" : ""} · click one for what to do` : ""}</span></div>
        <div id="uaF">${F.length ? shown.map((f, i) => findingRow(f, i, true)).join("") +
          (F.length > 6 ? `<div class="ua-more"><button class="ghost sm" id="uaMore">${UA.showAll ? "Show fewer" : `Show all ${F.length}`}</button></div>` : "")
          : `<div class="callout okc" style="margin:0">${IC("check")}<div><b>Nothing unusual.</b> No password guessing, unusual sign-in times, remote access from the internet or account changes in this period.</div></div>`}</div></div>

      <div class="card c8"><h3>When people use this PC <span class="sub">Sign-ins by day and hour</span></h3>${heat(d.heat, [].concat(...d.users.map(u => u.odd_cells)))}${legend()}${insights(d)}</div>
      <div class="card c4"><h3>How people sign in</h3>${bars(methods)}
        ${Object.keys(fails).length ? `<h3 class="mt">Why sign-ins failed</h3>${bars(fails, "bad")}` : ""}</div>

      <div class="card c12"><div class="ua-sec-h"><h3>People</h3><span class="sub mute">Click someone to see everything about their activity</span></div>
        <div class="ua-people">${d.users.map(personCard).join("") || EMPTY("No sign-ins found", "Nobody signed in to this PC in this period.")}</div></div>
    </div>`;
  const fl = Q("#uaF"); wireFindings(fl, F);
  const more = Q("#uaMore"); if (more) more.onclick = e => { e.stopPropagation(); UA.showAll = !UA.showAll; drawUsers(); };
  QA("#uaBody .ua-person").forEach(c => c.onclick = () => openPerson(c.dataset.k));
  animateBars(Q("#uaBody"));
  const n = s.attention, b = Q("#nb-users"); if (b) { b.textContent = n; b.classList.toggle("hide", !n); }
}

function insights(d) {
  const flat = []; d.heat.forEach((r, di) => r.forEach((v, h) => flat.push({di, h, v})));
  const total = flat.reduce((a, x) => a + x.v, 0); if (!total) return "";
  const byHour = Array.from({length: 24}, (_, h) => d.heat.reduce((a, r) => a + r[h], 0));
  const peak = byHour.indexOf(Math.max(...byHour)), night = byHour.slice(0, 5).reduce((a, b) => a + b, 0);
  const byDay = d.heat.map(r => r.reduce((a, b) => a + b, 0)), wk = byDay.slice(0, 5).reduce((a, b) => a + b, 0);
  const fmtH = h => new Date(2000, 0, 1, h).toLocaleTimeString([], {hour: "numeric"});
  return `<div class="ua-insight"><div><i>${IC("clock")}</i><span>Busiest time: <b>${fmtH(peak)} - ${fmtH(peak + 1)}</b></span></div>
    <div><i>${IC("users")}</i><span><b>${Math.round(wk / total * 100)}%</b> of sign-ins on weekdays</span></div>
    <div><i style="${night ? "background:var(--warnSoft);color:var(--warn)" : ""}">${IC("alert")}</i><span><b>${night}</b> sign-in${night === 1 ? "" : "s"} between midnight and 5 AM</span></div></div>`;
}

function personCard(u) {
  const st = {attention: ["p-bad", "Needs attention"], unusual: ["p-warn", "Something unusual"], normal: ["p-ok", "Looks normal"]}[u.status];
  const top = u.findings[0];
  return `<div class="ua-person st-${u.status}" data-k="${E(u.key)}">
    <div class="ua-ph"><div class="av" style="background:${u.unknown ? "#64748b" : avc(u.display)}">${u.unknown ? "?" : initial(u.display)}</div>
      <div class="t"><b>${E(shortName(u))}</b><span>${u.unknown ? "Names that don't exist on this PC" : (u.admin ? "Administrator" : "Standard user") + (u.last_signin ? " · last in " + ago2(u.last_signin) : "")}</span></div>
      <span class="pill ${st[0]}">${st[1]}</span></div>
    <div class="ua-ps"><div><b>${num2(u.signins)}</b><span>Sign-ins</span></div><div><b class="${u.failed ? "warn-t2" : ""}">${num2(u.failed)}</b><span>Wrong passwords</span></div>
      <div><b class="${u.remote ? "warn-t2" : ""}">${num2(u.remote)}</b><span>Remote Desktop</span></div></div>
    ${u.signins ? heat(u.heat, u.odd_cells, false) + `<div class="ua-mini-cap"><span>Midnight</span><span>Noon</span><span>11 PM</span></div>` : ""}
    ${top ? `<div class="ua-pf">${IC(SEVI[top.sev])}<span>${E(top.title)}</span>${u.findings.length > 1 ? `<em>+${u.findings.length - 1} more</em>` : ""}</div>` : ""}
  </div>`;
}

function openPerson(key) {
  const u = UA.data && UA.data.users.find(x => x.key === key); if (!u) return;
  const o = document.createElement("div"); o.className = "overlay";
  const st = {attention: ["p-bad", "Needs attention"], unusual: ["p-warn", "Something unusual"], normal: ["p-ok", "Looks normal"]}[u.status];
  const P = u.programs, period = UA.data.days === 1 ? "24 hours" : UA.data.days + " days";
  const plist = (arr, btn) => `<div class="ua-plist">${arr.map((p, i) => `<div><div class="nm"><b>${E(p.name)}</b><span title="${E(p.path)}">${E(p.path)}</span></div>
     ${p.count ? `<span class="mute" style="font-size:12px;white-space:nowrap">${num2(p.count)}×</span>` : ""}${p.new ? `<span class="bdg b-warn">New</span>` : ""}
     ${btn ? `<button class="ghost sm" data-safe="${E(p.path)}">${IC("shield")}Is this safe?</button>` : ""}</div>`).join("")}</div>`;
  o.innerHTML = `<div class="drawer ua-drawer"><div class="dh"><div class="row">
      <div class="av" style="background:${u.unknown ? "#64748b" : avc(u.display)}">${u.unknown ? "?" : initial(u.display)}</div>
      <div style="min-width:0"><h2>${E(shortName(u))}</h2><div class="rule">${u.unknown ? "Sign-in attempts with account names that don't exist on this PC" :
        `${u.admin ? "Administrator" : "Standard user"} · ${u.domain ? E(u.domain) + " · " : ""}active on ${u.active_days} day${u.active_days === 1 ? "" : "s"} in the last ${period}`}</div>
        <span class="pill ${st[0]}" style="margin:8px 0 0">${st[1]}</span></div>
      <button class="ghost sm x" data-close>${IC("x")}</button></div></div>
    <div class="dbody">
      <div class="ua-stats"><div><b>${num2(u.signins)}</b><span>Sign-ins</span></div><div><b class="${u.failed ? "warn-t2" : ""}">${num2(u.failed)}</b><span>Wrong passwords</span></div>
        <div><b>${num2(u.remote)}</b><span>Remote Desktop</span></div><div><b style="font-size:14px;line-height:1.9">${u.last_signin ? ago2(u.last_signin) : "-"}</b><span>Last sign-in</span></div></div>
      <div class="box"><h4>${IC("alert")}What we noticed</h4>${u.findings.length ? `<div id="upF">${u.findings.map((f, i) => findingRow(f, i, false)).join("")}</div>` :
        `<div class="callout okc" style="margin:0">${IC("check")}<div>Nothing unusual for this person in the last ${period}.</div></div>`}</div>
      ${u.signins ? `<div class="box"><h4>${IC("clock")}When they use this PC</h4>${heat(u.heat, u.odd_cells)}${legend()}</div>` : ""}
      ${Object.keys(u.methods).length || Object.keys(u.fail_reasons).length ? `<div class="box"><h4>${IC("login")}How they sign in</h4>${bars(u.methods)}
        ${Object.keys(u.fail_reasons).length ? `<h4 style="margin-top:14px">${IC("key")}Failed sign-ins</h4>${bars(u.fail_reasons, "bad")}` : ""}</div>` : ""}
      ${u.ips.length ? `<div class="box"><h4>${IC("remote")}Signed in from other devices</h4><table class="ua-iptable"><tr><th>Address</th><th>Where</th><th>How</th><th>Times</th><th>Last</th></tr>
        ${u.ips.map(x => `<tr><td class="code">${E(x.ip)}</td><td><span class="ua-where ${x.kind}">${x.kind === "internet" ? "Internet" : "Your network"}</span></td><td>${E(x.how)}</td><td>${x.count}</td><td>${ago2(x.last)}</td></tr>`).join("")}</table></div>` : ""}
      ${P.started ? `<div class="box"><h4>${IC("play")}Programs they ran (last 7 days)</h4>
        <p style="margin-bottom:10px">${num2(P.started)} program starts · ${num2(P.distinct)} different programs</p>
        ${Object.keys(P.shells).length ? `<div class="ua-chips" style="margin-bottom:12px">${Object.entries(P.shells).map(([k, v]) => `<span class="bdg">${E(k)} · ${v}</span>`).join("")}</div>` : ""}
        ${P.risky.length ? `<h4 style="margin-top:4px">${IC("alert")}From Downloads or Temp</h4>${plist(P.risky, true)}` : ""}
        ${P.new.length ? `<h4 style="margin-top:14px">${IC("star")}New this week</h4>${plist(P.new.map(p => ({...p, new: false})), true)}` : ""}
        <h4 style="margin-top:14px">${IC("star")}Used the most</h4>${plist(P.top, false)}</div>` : ""}
      ${u.timeline.length ? `<div class="box"><h4>${IC("clock")}Recent activity</h4><div class="ua-tl">${u.timeline.slice(0, 40).map(x => `<div><i class="${x.kind}"></i><span>${E(x.text)}</span><em>${fmtWhen(x.t)}</em></div>`).join("")}</div></div>` : ""}
    </div></div>`;
  document.body.append(o);
  const close = () => o.remove();
  o.onclick = e => { if (e.target === o) close(); };
  o.querySelector("[data-close]").onclick = close;
  const f = o.querySelector("#upF"); if (f) wireFindings(f, u.findings);
  o.querySelectorAll("[data-safe]").forEach(b => b.onclick = () => { close(); checkPath(b.dataset.safe); });
  animateBars(o);
}
function checkPath(p) {
  goto("scan");
  setTimeout(() => { if (fn("pickKind")) pickKind("check"); const i = Q("#sPath"); if (i) i.value = p; if (fn("startScan")) startScan(); }, 150);
}

/* ================= SECURITY CHECKUP page ================= */
Q("#ckRun").onclick = () => loadCheckup(true);
Q("#ckPrint").onclick = () => window.print();
const ST_ICON = {ok: "check", warn: "alert", bad: "x"};
function ring(score, size = 132) {
  const r = size / 2 - 10, C = 2 * Math.PI * r, col = score >= 80 ? "#10b981" : score >= 55 ? "#f59e0b" : "#ef4444";
  return `<div class="ck-ring"><svg viewBox="0 0 ${size} ${size}"><circle class="tr" cx="${size / 2}" cy="${size / 2}" r="${r}"/>
    <circle class="v" cx="${size / 2}" cy="${size / 2}" r="${r}" stroke="${col}" stroke-dasharray="${C}" stroke-dashoffset="${C}" data-off="${C * (1 - score / 100)}"/></svg><b>${score}<small>%</small></b></div>`;
}
const animRing = root => requestAnimationFrame(() => requestAnimationFrame(() => root.querySelectorAll(".ck-ring .v").forEach(c => c.style.strokeDashoffset = c.dataset.off)));
function ckRow(c) {
  const nist = c.nist_id ? `<span style="font-size:10px;padding:1px 5px;margin-left:6px;background:var(--surface2);color:var(--text2);border-radius:4px;font-family:monospace;letter-spacing:0.3px">${E(c.nist_id)}</span>` : "";
  return `<div class="ck-row"><div class="ck-st ${c.state}">${IC(ST_ICON[c.state])}</div><div class="t"><b>${E(c.title)}${nist}</b><span>${E(c.text)}</span></div>
    ${c.fix ? `<button class="${c.state === "bad" ? "btn" : "ghost"} sm no-print" data-fix='${E(JSON.stringify(c.fix))}'>${c.fix.link ? IC("ext") : ""}${E(c.fix.label)}</button>` : ""}</div>`;
}
function wireFixes(root) { root.querySelectorAll("[data-fix]").forEach(b => b.onclick = e => { e.stopPropagation(); doFix(JSON.parse(b.dataset.fix)); }); }
const NIST_META = {
  Identify: {desc: "Account & privilege hygiene", icon: "users"},
  Protect: {desc: "Defenses, ASR & baseline", icon: "shield"},
  Detect: {desc: "Scanning & telemetry", icon: "eye"},
  Respond: {desc: "Incident & threat response", icon: "alert"},
  Recover: {desc: "Protection self-test", icon: "check"}
};
function nistCards(nist) {
  if (!nist || !Object.keys(nist).length) return "";
  const cols = Object.entries(nist).map(([fn, st]) => {
    const meta = NIST_META[fn] || {desc: "", icon: "shield"};
    const col = st.score >= 80 ? "var(--ok)" : st.score >= 50 ? "var(--warn)" : "var(--bad)";
    return `<div style="flex:1;min-width:130px;background:var(--surface);border-radius:8px;padding:12px;border:1px solid var(--line);box-shadow:0 1px 3px rgba(0,0,0,0.05)">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
        <b style="font-size:13px">${E(fn)}</b>
        <span style="font-weight:700;font-size:13px;color:${col}">${st.score}%</span>
      </div>
      <div class="tr" style="height:5px;background:var(--surface2);border-radius:3px;overflow:hidden;margin-bottom:8px">
        <i style="display:block;height:100%;background:${col};width:0;transition:width 0.8s ease" data-w="${st.score}%"></i>
      </div>
      <div style="font-size:11.5px;color:var(--text2);line-height:1.3">${meta.desc}</div>
      <div style="font-size:11px;color:var(--mute);margin-top:4px">${st.ok} of ${st.total} passing</div>
    </div>`;
  }).join("");
  return `<div class="card c12" style="background:linear-gradient(180deg, var(--surface) 0%, var(--surface2) 100%);border:1px solid var(--line)">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px">
      <div>
        <h3 style="margin:0;font-size:15px;display:flex;align-items:center;gap:6px">${IC("shield")}NIST Cybersecurity Framework (CSF 2.0) Posture</h3>
        <span class="sub mute" style="font-size:12px">Compliance alignment across Core NIST Functions</span>
      </div>
      <span class="pill p-ok" style="font-size:11px">CSF 2.0 Alignment</span>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">${cols}</div>
  </div>`;
}
async function loadCheckup(refresh) {
  const body = Q("#ckBody");
  if (refresh || !body.innerHTML) body.innerHTML = `<div class="card"><div class="ua-loading"><div class="ua-spin"></div><b>Checking your settings…</b><span>This takes a few seconds.</span></div></div>`;
  let d; try { d = await GET("/api/checkup" + (refresh ? "?refresh=true" : "")); }
  catch (e) { body.innerHTML = `<div class="callout">${IC("alert")}<div>${E(e.message)}</div></div>`; return; }
  Q("#ckPH").textContent = "Checked " + new Date(d.time).toLocaleString();
  const groups = {}; d.checks.forEach(c => (groups[c.group] = groups[c.group] || []).push(c));
  const head = d.bad ? "Some important settings need fixing" : d.warn ? "Almost there" : "Everything looks good";
  body.innerHTML = `<div class="d12 stagger">
    <div class="card c12 ck-hero">${ring(d.score)}<div><h2>${head}</h2><p>${d.ok} of ${d.total} checks look good.${d.windows_details ? "" : " Windows details are still loading - check again in a moment."}</p>
      <div class="ck-counts">${d.bad ? `<span class="ck-count bad">${IC("x", 'style="width:14px;height:14px"')}${d.bad} to fix</span>` : ""}${d.warn ? `<span class="ck-count warn">${IC("alert", 'style="width:14px;height:14px"')}${d.warn} worth a look</span>` : ""}
        <span class="ck-count ok">${IC("check", 'style="width:14px;height:14px"')}${d.ok} good</span></div></div>
      <span class="mute" style="font-size:12.5px;align-self:end">Checked ${ago2(d.time)}</span></div>
    ${nistCards(d.nist_summary)}
    ${Object.entries(groups).map(([g, cs]) => `<div class="card c6"><h3>${g === "Windows" ? "Windows" : "Security Console"} <span class="sub">${cs.filter(c => c.state === "ok").length} of ${cs.length} good</span></h3>
      <div class="ck-list">${cs.map(ckRow).join("")}</div></div>`).join("")}
    <div class="card c12"><div class="callout info" style="margin:0">${IC("info")}<div>Buttons marked ${IC("ext", 'style="width:14px;height:14px;vertical-align:-2px"')} open the right page in Windows Settings or Windows Security - Windows may ask before opening it.
      Security Console never changes Windows settings by itself.</div></div></div></div>`;
  wireFixes(body); animRing(body); animateBars(body); setCheckBadge(d);
}
function setCheckBadge(d) { const b = Q("#nb-checkup"); if (b) { b.textContent = d.bad; b.classList.toggle("hide", !d.bad); } }
function doFix(f) {
  if (f.link) { const a = document.createElement("a"); a.href = f.link; document.body.append(a); a.click(); a.remove(); say("Opening Windows settings…", "ext"); return; }
  const later = () => setTimeout(() => { if (pg() === "checkup") loadCheckup(true); else homeExtras(true); }, 3000);
  switch (f.action) {
    case "realtime": { const t = Q("#rtToggle"); if (t && !t.checked) { t.checked = true; t.dispatchEvent(new Event("change")); } later(); break; }
    case "resume": fn("resumeAll") ? resumeAll() : fetch("/api/power/resume", {method: "POST"}); later(); break;
    case "defs": fn("maint") && maint("update_signatures"); break;
    case "scan": fn("quickScan") && quickScan(); break;
    case "selftest": fn("maint") && maint("selftest"); break;
    case "threats": goto("threats"); break;
    default: if (String(f.action).startsWith("go:")) goto(f.action.slice(3));
  }
}

/* ================= DASHBOARD extras ================= */
const home = Q("#p-home .d12");
let HX = {t: 0};
if (home) {
  home.insertAdjacentHTML("afterbegin", `<div class="card c12 gs hide" id="gsCard"></div>`);
  const kpis = home.querySelectorAll(":scope > .kpi"), anchor = kpis[kpis.length - 1];
  const html = `<div class="card c7" id="ckCard"><h3>Security checkup <a class="sub link" data-go="checkup">See all →</a></h3><div id="ckMini"><div class="skel"></div><div class="skel"></div></div></div>
    <div class="card c5" id="ppCard"><h3>People on this PC <a class="sub link" data-go="users">Details →</a></h3><div id="ppMini"><div class="skel"></div><div class="skel"></div></div></div>`;
  anchor ? anchor.insertAdjacentHTML("afterend", html) : home.insertAdjacentHTML("beforeend", html);
  home.querySelectorAll("[data-go]").forEach(a => a.onclick = () => goto(a.dataset.go));
}
async function homeExtras(force) {
  if (!home || (!force && Date.now() - HX.t < 60000)) return;
  HX.t = Date.now();
  gettingStarted().catch(() => {});
  GET("/api/checkup").then(d => {
    setCheckBadge(d);
    const issues = d.checks.filter(c => c.state !== "ok").slice(0, 4);
    Q("#ckMini").innerHTML = `<div class="ck-mini">${ring(d.score, 92)}<div><h4>${d.ok} of ${d.total} settings look good</h4>
      <p>${d.bad ? `${d.bad} need fixing` : d.warn ? `${d.warn} worth a look` : "Nothing to fix right now."}</p></div></div>
      ${issues.length ? `<div class="ck-list mt">${issues.map(ckRow).join("")}</div>` : `<div class="callout okc">${IC("check")}<div>Your PC's security settings look good.</div></div>`}`;
    wireFixes(Q("#ckMini")); animRing(Q("#ckMini"));
  }).catch(e => { Q("#ckMini").innerHTML = `<p class="mute">${E(e.message)}</p>`; });
  GET("/api/users/report?days=14").then(r => {
    const el = Q("#ppMini");
    if (!r.data) { el.innerHTML = `<div class="ua-loading" style="padding:24px"><div class="ua-spin"></div><span>Reading sign-in records…</span></div>`; if (r.status === "building") setTimeout(() => homeExtras(true), 4000); return; }
    if (!UA.data || UA.days === 14) UA.data = UA.data || r.data;
    const us = r.data.users.slice(0, 5), sum = r.data.summary;
    const st = {attention: ["p-bad", "Needs attention"], unusual: ["p-warn", "Unusual"], normal: ["p-ok", "Normal"]};
    el.innerHTML = us.length ? `<div class="ua-plite">${us.map(u => `<div data-k="${E(u.key)}"><div class="av" style="background:${u.unknown ? "#64748b" : avc(u.display)}">${u.unknown ? "?" : initial(u.display)}</div>
        <div class="t"><b>${E(shortName(u))}</b><span>${u.last_signin ? "Last signed in " + ago2(u.last_signin) : u.failed ? `${u.failed} failed attempts` : "No sign-ins"}${u.findings[0] ? " · " + E(u.findings[0].title) : ""}</span></div>
        <span class="pill ${st[u.status][0]}">${st[u.status][1]}</span></div>`).join("")}</div>
        <p class="mute" style="font-size:12px;margin-top:8px">${num2(sum.signins)} sign-ins and ${num2(sum.failed)} wrong passwords in the last 14 days.</p>`
      : `<p class="mute">No sign-ins found in the last 14 days.</p>`;
    el.querySelectorAll("[data-k]").forEach(x => x.onclick = () => { UA.days = 14; UA.data = r.data; goto("users"); setTimeout(() => openPerson(x.dataset.k), 350); });
    const b = Q("#nb-users"); if (b) { b.textContent = sum.attention; b.classList.toggle("hide", !sum.attention); }
  }).catch(e => { Q("#ppMini").innerHTML = `<p class="mute">${E(e.message)}</p>`; });
}

async function gettingStarted() {
  const card = Q("#gsCard"); if (!card || LS("ua_gs_hidden")) { card && card.classList.add("hide"); return; }
  const [rt, ov, jobs] = await Promise.all([GET("/api/realtime").catch(() => ({})), GET("/api/overview").catch(() => ({})), GET("/api/jobs?limit=60").catch(() => [])]);
  const tested = jobs.some(j => j.target === "Protection self-test" && j.state === "done" && j.result && j.result.self_test && j.result.self_test.ok);
  const steps = [
    {t: "Turn on real-time protection", d: "Checks new files and programs within seconds", done: !!rt.enabled, run: () => doFix({action: "realtime"})},
    {t: "Run your first scan", d: "Quick scan: Downloads, Desktop and Temp", done: !!(ov && ov.last_scan), run: () => fn("quickScan") && quickScan()},
    {t: "Test your protection", d: "A harmless 10-second check", done: tested, run: () => fn("maint") && maint("selftest")},
    {t: "Do a security checkup", d: "See which settings need attention", done: LS("ua_checkup_seen"), run: () => goto("checkup")},
    {t: "Review startup programs", d: "Turn off what doesn't need to start", done: LS("ua_startup_seen"),
     run: () => { localStorage.setItem("ua_startup_seen", "1"); goto("check"); setTimeout(() => fn("hunt") && hunt("startup_items", "Startup programs"), 300); }},
    {t: "See who uses this PC", d: "Sign-ins and anything unusual", done: LS("ua_users_seen"), run: () => goto("users")}];
  const n = steps.filter(s => s.done).length;
  if (n === steps.length) { card.classList.add("hide"); return; }
  card.classList.remove("hide");
  card.innerHTML = `<div class="gs-h"><div class="ic">${IC("star")}</div><div><b>Get the most out of Security Console</b><span>${steps.length - n} quick step${steps.length - n > 1 ? "s" : ""} left to set up your protection.</span></div>
      <div class="gs-prog"><div class="tr"><i style="width:${n / steps.length * 100}%"></i></div><small>${n} of ${steps.length} done</small></div>
      <button class="gs-x" title="Hide" id="gsHide">${IC("x")}</button></div>
    <div class="gs-steps">${steps.map((s, i) => `<div class="gs-step ${s.done ? "done" : ""}"><span class="ck">${IC("check")}</span><div class="t"><b>${s.t}</b><span>${s.d}</span></div>
      ${s.done ? "" : `<button class="btn sm" data-gs="${i}">${i === 0 ? "Turn on" : i === 1 ? "Scan" : i === 2 ? "Test" : "Open"}</button>`}</div>`).join("")}</div>`;
  card.querySelectorAll("[data-gs]").forEach(b => b.onclick = () => { steps[+b.dataset.gs].run(); setTimeout(() => homeExtras(true), 2500); });
  Q("#gsHide").onclick = () => { localStorage.setItem("ua_gs_hidden", "1"); card.classList.add("hide"); say("Hidden. You can find these steps on the Security checkup page.", "info"); };
}

/* ---- load the VirusTotal add-on (1.9) ---- */
(() => {
  if (Q('script[src*="addon_vt.js"]')) return;
  const l = document.createElement("link"); l.rel = "stylesheet"; l.href = "/static/addon_vt.css?v=1.9"; document.head.append(l);
  const s = document.createElement("script"); s.src = "/static/addon_vt.js?v=1.9"; document.body.append(s);
})();

/* ---- start ---- */
if (pg() === "home") homeExtras(true);
GET("/api/checkup").then(setCheckBadge).catch(() => {});
})();
