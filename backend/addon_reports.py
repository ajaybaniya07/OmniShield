"""
OmniShield add-on 1.8
  * User activity: sign-ins, wrong passwords, remote access, account changes and the
    programs each Windows user runs - with plain-English "unusual activity" findings.
  * Security checkup: Windows and OmniShield settings, with one-click fixes.
Loaded by main.py (INSTALL-ADDON.bat adds the hook). Everything here is read-only:
it never changes accounts or settings by itself.
"""
import collections
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import xml.etree.ElementTree as ET

from fastapi import HTTPException

M = None                      # the main OmniShield module (set by register)
SAMPLE_EVENTS = None          # tests only: {"Security": [...], "Sysmon": [...]}
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SEC_IDS = [4624, 4625, 4740, 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4756, 1102]

LOGON_TYPES = {2: "At the PC", 3: "Over the network", 7: "Unlocked the PC", 8: "Over the network",
               9: "As a different user", 10: "Remote Desktop", 11: "At the PC (saved sign-in)",
               12: "Remote Desktop (saved sign-in)", 13: "Unlocked (saved sign-in)"}
INTERACTIVE = {2, 7, 10, 11, 12, 13}
REMOTE = {10, 12}
FAIL_REASON = {"0xc000006a": "Wrong password", "0xc000006d": "Wrong user name or password",
               "0xc0000064": "Account doesn't exist", "0xc0000234": "Account is locked",
               "0xc0000072": "Account is turned off", "0xc000006f": "Not allowed at this time",
               "0xc0000070": "Not allowed on this PC", "0xc0000071": "Password has expired",
               "0xc0000193": "Account has expired", "0xc0000224": "Must change password",
               "0xc000015b": "Not allowed to sign in this way", "0xc0000133": "PC clock is wrong"}
SYSTEM_NAMES = {"system", "local service", "network service", "anonymous logon", "-", "", "iusr",
                "defaultaccount", "wdagutilityaccount"}
SYSTEM_DOMAINS = {"nt authority", "window manager", "font driver host", "nt service"}
RISKY_DIR = re.compile(r"\\(downloads|temp|tmp|users\\public|\$recycle\.bin)\\", re.I)
SHELLS = {"powershell.exe": "PowerShell", "pwsh.exe": "PowerShell", "cmd.exe": "Command Prompt",
          "wscript.exe": "Windows Script Host", "cscript.exe": "Windows Script Host", "mshta.exe": "HTML app (mshta)",
          "rundll32.exe": "rundll32", "regsvr32.exe": "regsvr32"}

# ---- plain-English findings ------------------------------------------------- #
F = {
    "burst_success": ("critical", "Wrong passwords, then a successful sign-in",
        ["If that sign-in wasn't you, change this account's password from a trusted device straight away.",
         "Open Settings > Accounts > Other users and remove any account you don't recognise.",
         "Turn off Remote Desktop if you don't use it (see Security checkup).", "Run a Full scan."],
        "It was probably you if you mistyped a few times and then got it right."),
    "burst": ("high", "Someone may be guessing a password",
        ["If it wasn't you, change this account's password.",
         "If the attempts came from another device, check that device too.",
         "Turn off Remote Desktop if you don't use it (see Security checkup).",
         "Use a long password, or a PIN with Windows Hello."],
        "Can happen after you change your password, if an app or mapped drive still uses the old one."),
    "lockout": ("high", "Account was locked after too many wrong passwords",
        ["If it wasn't you, change the password once it unlocks.", "Check the 'Signed in from' list below for addresses you don't know."],
        "Normal if you forgot your password and kept trying."),
    "odd_hours": ("medium", "Signed in at an unusual time",
        ["If that was you, there's nothing to do.",
         "If not, change this account's password and check that Remote Desktop is off."],
        "Common if you worked late, or unlocked the PC when it woke up for updates."),
    "late_night": ("low", "Signed in late at night",
        ["If that was you, there's nothing to do.", "If not, change this account's password."],
        "Usually just a late session."),
    "rdp_local": ("medium", "Remote Desktop sign-in",
        ["If you use Remote Desktop yourself, this is normal.",
         "If not, turn Remote Desktop off (Security checkup) and change the password."],
        "Normal if you connect from another PC at home."),
    "rdp_internet": ("high", "Remote sign-in from the internet",
        ["If you didn't do this, turn off Remote Desktop now (Security checkup) and change the password.",
         "Ask whoever set up your router to close port 3389.", "Run a Full scan."],
        "Only normal if you deliberately connect to this PC from outside your home."),
    "net_internet": ("high", "Sign-in over the internet",
        ["If you don't recognise the address, change this account's password.",
         "Check that file sharing and Remote Desktop aren't open to the internet."],
        "Rare on a home PC."),
    "new_account": ("high", "New account created",
        ["If you didn't create it, open Settings > Accounts > Other users and remove it.", "Change your own password."],
        "Normal if you or someone you trust just added a user."),
    "admin_added": ("high", "Given administrator rights",
        ["If you didn't do this, open Settings > Accounts > Other users, choose the account and change it to 'Standard user'.",
         "Change your password and run a Full scan."],
        "Normal if you just made someone an administrator on purpose."),
    "rdp_group": ("medium", "Allowed to use Remote Desktop",
        ["If you didn't allow this, remove the account from 'Remote Desktop Users' or turn Remote Desktop off."],
        "Normal if you set up Remote Desktop for this person."),
    "pwd_reset": ("medium", "Password changed by another account",
        ["If you didn't expect this, check who did it (below) and change the password again yourself."],
        "Normal if an administrator reset a forgotten password."),
    "guest_on": ("high", "Guest account turned on",
        ["Turn the Guest account off unless you really need it - it lets anyone use this PC."],
        "Rarely needed on a modern PC."),
    "account_deleted": ("medium", "Account deleted",
        ["If you didn't delete it, check the other accounts on this PC and change your password."],
        "Normal if you removed an old account."),
    "log_cleared": ("critical", "Security log was cleared",
        ["If you didn't clear it, run a Full scan and change your passwords from a trusted device.",
         "Review the other findings from around the same time."],
        "Only normal if you used a 'PC cleaner' tool or cleared logs on purpose."),
    "risky_programs": ("medium", "New programs ran from Downloads or Temp",
        ["Use 'Is this safe?' on each program listed below.", "Uninstall or delete anything you don't recognise."],
        "Installers you just downloaded show up here - that's normal."),
    "encoded_ps": ("high", "Hidden PowerShell command",
        ["Look at the program that started it (below).", "If you don't recognise it, run a Quick scan and block it."],
        "Some admin and update tools do this."),
}
TITLE_KEY = {v[1]: k for k, v in F.items()}


# --------------------------------------------------------------------------- #
# Windows event log reading
# --------------------------------------------------------------------------- #
def _ts(s: str):
    s = (s or "").rstrip("Z")
    if "." in s:
        a, b = s.split(".", 1)
        s = a + "." + b[:6]
    try:
        return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc).astimezone().replace(tzinfo=None)
    except ValueError:
        return None


def _parse(x) -> dict | None:
    try:
        root = ET.fromstring(x) if isinstance(x, str) else x
    except ET.ParseError:
        return None
    s = root.find(NS + "System")
    if s is None:
        return None
    tc = s.find(NS + "TimeCreated")
    d = {"_id": int((s.findtext(NS + "EventID") or "0").strip() or 0),
         "_t": _ts(tc.get("SystemTime", "") if tc is not None else "")}
    ed = root.find(NS + "EventData")
    if ed is not None:
        for n in ed.findall(NS + "Data"):
            d[n.get("Name", "")] = (n.text or "").strip()
    ud = root.find(NS + "UserData")
    if ud is not None:
        for n in ud.iter():
            if len(n) == 0:
                d[n.tag.split("}")[-1]] = (n.text or "").strip()
    return d if d["_t"] else None


def read_events(channel: str, ids: list, days: float, limit: int) -> list[dict]:
    if SAMPLE_EVENTS is not None:
        since = dt.datetime.now() - dt.timedelta(days=days)
        key = "Sysmon" if channel == SYSMON else channel
        return [e for e in SAMPLE_EVENTS.get(key, []) if e["_id"] in ids and e["_t"] >= since][:limit]
    if os.name != "nt":
        return []
    xp = "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + \
         f") and TimeCreated[timediff(@SystemTime) <= {int(days * 86400000)}]]]"
    w = getattr(M, "win32evtlog", None)
    if w is not None:
        try:
            h = w.EvtQuery(channel, w.EvtQueryChannelPath | w.EvtQueryReverseDirection, xp)
            out = []
            while len(out) < limit:
                try:
                    batch = w.EvtNext(h, 200)
                except Exception:
                    break
                if not batch:
                    break
                out += [e for e in (_parse(w.EvtRender(b, w.EvtRenderEventXml)) for b in batch) if e]
            return out
        except Exception as e:
            M.log.warning("event query %s via pywin32 failed (%s) - trying wevtutil", channel, e)
    r = M.run(["wevtutil", "qe", channel, f"/q:{xp}", "/f:xml", "/e:Events", f"/c:{limit}", "/rd:true"], timeout=240)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "").strip()[:300] or f"Couldn't read the {channel} log")
    try:
        root = ET.fromstring(r.stdout or "<Events/>")
    except ET.ParseError:
        return []
    return [e for e in (_parse(x) for x in root) if e]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def is_system(user: str, domain: str = "") -> bool:
    u = (user or "").strip().lower()
    return (u in SYSTEM_NAMES or u.endswith("$") or u.startswith(("dwm-", "umfd-"))
            or (domain or "").strip().lower() in SYSTEM_DOMAINS)


def ip_kind(ip: str):
    ip = (ip or "").strip()
    if not ip or ip in ("-", "::1", "127.0.0.1", "0.0.0.0", "::"):
        return None
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    a = getattr(a, "ipv4_mapped", None) or a
    if a.is_loopback or a.is_unspecified:
        return None
    return "local" if (a.is_private or a.is_link_local) else "internet"


def bn(p: str) -> str:
    """File name from a Windows path (works on any OS)."""
    return re.split(r"[\\/]", p or "")[-1]


def when(t: dt.datetime) -> str:
    return t.strftime("%a %d %b, ") + t.strftime("%I:%M %p").lstrip("0")


def _own(path: str) -> bool:
    try:
        return any(M.under(path, d) for d in M.own_dirs())
    except Exception:
        return False


_LOCAL = {"data": None, "t": 0.0, "lock": threading.Lock()}
LOCAL_PS = r'''
$ErrorActionPreference = "SilentlyContinue"
# SecurityConsole internal (sc-internal): accounts and remote access for the security checkup
$o = [ordered]@{}
$g = Get-LocalUser -Name Guest
$o.guest = [bool]$g.Enabled
$o.admins = @(Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { "$($_.Name)" })
$o.users = @(Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { "$($_.Name)" })
$o.nopass = @(Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordRequired } | ForEach-Object { "$($_.Name)" })
$ts = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$o.rdp = ($ts.fDenyTSConnections -eq 0)
$wl = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$o.autologon = ("$($wl.AutoAdminLogon)" -eq "1")
$smb = Get-SmbServerConfiguration
$o.smb1 = [bool]$smb.EnableSMB1Protocol
$mp = Get-MpPreference
$o.asr = [ordered]@{ count = @($mp.AttackSurfaceReductionRules_Ids).Count; block = @($mp.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 1 -or $_ -eq 6 }).Count }
$o | ConvertTo-Json -Compress
'''


def local_info(refresh: bool = False) -> dict:
    with _LOCAL["lock"]:
        if _LOCAL["data"] is not None and not refresh and time.time() - _LOCAL["t"] < 600:
            return _LOCAL["data"]
        data = {}
        if os.name == "nt":
            try:
                r = M.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", LOCAL_PS], timeout=90)
                data = json.loads((r.stdout or "").strip() or "{}")
            except Exception:
                M.log.exception("local account info")
        for k in ("admins", "users", "nopass"):
            if isinstance(data.get(k), str):
                data[k] = [data[k]]
        _LOCAL.update(data=data, t=time.time())
        return data


# --------------------------------------------------------------------------- #
# The report
# --------------------------------------------------------------------------- #
def _finding(u, key, when_t, what, extra=None):
    sev, title, steps, fp = F[key]
    f = {"key": key, "sev": sev, "title": title, "what": what, "when": when_t.isoformat(timespec="seconds") if when_t else None,
         "steps": steps, "fp": fp, "user": u["key"], "user_name": u["display"]}
    if extra:
        f.update(extra)
    u["findings"].append(f)


def build_report(days: int) -> dict:
    t0 = time.time()
    now = dt.datetime.now()
    host = (os.environ.get("COMPUTERNAME") or "").lower()
    notes = []
    try:
        sec = read_events("Security", SEC_IDS, days, 60000)
    except Exception as e:
        sec = []
        notes.append(f"Couldn't read the Windows Security log: {e}")
    try:
        sysm = read_events(SYSMON, [1], min(days, 7), 60000)
    except Exception:
        sysm = []
        notes.append("The activity monitor (Sysmon) log couldn't be read, so programs per person aren't shown.")
    if len(sec) >= 60000:
        notes.append("This PC has a lot of sign-in events, so only the most recent 60,000 were analysed.")
    sec.sort(key=lambda e: e["_t"])
    sysm.sort(key=lambda e: e["_t"])
    admins = {a.split("\\")[-1].lower() for a in (local_info().get("admins") or [])}
    users: dict[str, dict] = {}
    sid_names: dict[str, str] = {}

    def U(name, domain="", sid=""):
        name = (name or "").strip()
        domain = (domain or "").strip()
        key = (domain + "\\" + name).lower() if domain else name.lower()
        u = users.get(key)
        if u is None:
            disp = name if not domain or domain.lower() in (host, "microsoftaccount", ".") else f"{domain}\\{name}"
            u = users[key] = {"key": key, "name": name, "domain": domain, "display": disp, "sid": sid,
                              "signins": [], "failed": [], "events": [], "findings": [], "programs": [],
                              "admin": name.lower() in admins}
        if sid and not u["sid"]:
            u["sid"] = sid
        if sid:
            sid_names.setdefault(sid, key)
        return u

    def find(name="", domain="", sid=""):
        """Same person even when an event leaves out the computer name or only has the account ID."""
        if sid and sid in sid_names:
            return users[sid_names[sid]]
        n = (name or "").strip().lower()
        if n and n != "-":
            same = [u for u in users.values() if u["name"].lower() == n]
            if same and (not domain or len(same) == 1):
                if sid:
                    sid_names.setdefault(sid, same[0]["key"])
                return same[0]
            return U(name, domain, sid)
        return U(sid or "Unknown account", "", sid)

    last_logon: dict = {}
    for e in sec:
        i, t = e["_id"], e["_t"]
        if i == 4624:
            name, dom = e.get("TargetUserName", ""), e.get("TargetDomainName", "")
            if is_system(name, dom):
                continue
            try:
                lt = int(e.get("LogonType") or 0)
            except ValueError:
                continue
            ip = e.get("IpAddress", "")
            kind = ip_kind(ip)
            if lt not in INTERACTIVE and lt not in (8, 9) and not (lt == 3 and kind):
                continue
            u = U(name, dom, e.get("TargetUserSid", ""))
            if u["sid"]:
                sid_names[u["sid"]] = u["key"]
            k = (u["key"], lt)
            if k in last_logon and (t - last_logon[k]).total_seconds() < 4:
                continue  # Windows logs two events per admin sign-in
            last_logon[k] = t
            u["signins"].append({"t": t, "type": lt, "how": LOGON_TYPES.get(lt, f"Type {lt}"), "ip": ip if kind else "",
                                 "kind": kind or "", "ws": e.get("WorkstationName", "")})
        elif i == 4625:
            name, dom = e.get("TargetUserName", ""), e.get("TargetDomainName", "")
            if is_system(name, dom) and name not in ("", "-"):
                continue
            code = (e.get("SubStatus") or "").lower()
            if code in ("", "0x0", "0x00000000"):
                code = (e.get("Status") or "").lower()
            reason = FAIL_REASON.get(code, "Sign-in failed")
            ip = e.get("IpAddress", "")
            rec = {"t": t, "reason": reason, "ip": ip if ip_kind(ip) else "", "kind": ip_kind(ip) or "",
                   "ws": e.get("WorkstationName", ""), "typed": name}
            u = U("Unknown account names", "") if code == "0xc0000064" or not name.strip("- ") else find(name, dom)
            if code == "0xc0000064":
                u["unknown"] = True
            u["failed"].append(rec)
        elif i == 4740:
            u = find(e.get("TargetUserName", ""), "", e.get("TargetSid", ""))
            u["events"].append({"t": t, "kind": "bad", "text": "Account locked (too many wrong passwords)"})
            _finding(u, "lockout", t, f"Windows locked this account at {when(t)} after too many wrong passwords"
                     + (f" (from {e.get('TargetDomainName')})." if e.get("TargetDomainName") else "."))
        elif i in (4720, 4722, 4724, 4725, 4726):
            tgt = find(e.get("TargetUserName", ""), e.get("TargetDomainName", ""), e.get("TargetSid", ""))
            by = e.get("SubjectUserName", "") or "someone"
            if is_system(by):
                by = "Windows"
            if i == 4720:
                tgt["events"].append({"t": t, "kind": "bad", "text": f"Account created by {by}"})
                _finding(tgt, "new_account", t, f"The account '{tgt['display']}' was created by {by} at {when(t)}.")
            elif i == 4722:
                tgt["events"].append({"t": t, "kind": "info", "text": f"Account turned on by {by}"})
                if tgt["name"].lower() == "guest":
                    _finding(tgt, "guest_on", t, f"The Guest account was turned on by {by} at {when(t)}. Anyone can use it to sign in.")
            elif i == 4724:
                if (e.get("SubjectUserName", "").lower() != tgt["name"].lower()) and by != "Windows":
                    tgt["events"].append({"t": t, "kind": "warn", "text": f"Password reset by {by}"})
                    _finding(tgt, "pwd_reset", t, f"{by} set a new password for this account at {when(t)}.")
            elif i == 4725:
                tgt["events"].append({"t": t, "kind": "info", "text": f"Account turned off by {by}"})
            elif i == 4726:
                tgt["events"].append({"t": t, "kind": "warn", "text": f"Account deleted by {by}"})
                _finding(tgt, "account_deleted", t, f"The account '{tgt['display']}' was deleted by {by} at {when(t)}.")
        elif i in (4728, 4732, 4756):
            group = e.get("TargetUserName", "")
            g = group.lower()
            member_name = e.get("MemberName", "")
            if member_name.upper().startswith("CN="):
                member_name = member_name[3:].split(",")[0]
            sid = e.get("MemberSid", "")
            tgt = find(member_name if member_name and member_name != "-" else "", "", sid)
            by = e.get("SubjectUserName", "") or "someone"
            tgt["events"].append({"t": t, "kind": "warn", "text": f"Added to the '{group}' group by {by}"})
            if g in ("administrators", "domain admins", "enterprise admins", "backup operators", "hyper-v administrators"):
                tgt["admin"] = True
                _finding(tgt, "admin_added", t, f"This account was added to '{group}' by {by} at {when(t)}. "
                                                "Administrators can change anything on this PC.")
            elif g == "remote desktop users":
                _finding(tgt, "rdp_group", t, f"This account was allowed to use Remote Desktop by {by} at {when(t)}.")
        elif i == 1102:
            by = e.get("SubjectUserName") or "Someone"
            dom = e.get("SubjectDomainName", "")
            u = find(by, dom, e.get("SubjectUserSid", "")) if not is_system(by, dom) else U("Windows")
            u["events"].append({"t": t, "kind": "bad", "text": "Cleared the Windows Security log"})
            _finding(u, "log_cleared", t, f"{u['display']} cleared the Windows Security log at {when(t)}. "
                                          "Attackers do this to hide what they did.")

    # ---- programs per person (Sysmon) ---- #
    for e in sysm:
        who = e.get("User", "")
        if "\\" not in who:
            continue
        dom, name = who.split("\\", 1)
        if is_system(name, dom):
            continue
        img = e.get("Image", "")
        if not img or _own(img):
            continue
        u = find(name, dom)
        u["programs"].append({"t": e["_t"], "image": img, "cmd": e.get("CommandLine", ""), "parent": e.get("ParentImage", "")})

    # ---- program baseline: which programs are new for this person ---- #
    new_by_user: dict[str, dict] = {}
    with M._db_lock, M.db() as con:
        for u in users.values():
            if not u["programs"]:
                continue
            base = con.execute("SELECT since FROM addon_user_baseline WHERE user=?", (u["key"],)).fetchone()
            if base is None:
                con.execute("INSERT INTO addon_user_baseline(user,since) VALUES(?,?)", (u["key"], now.isoformat(timespec="seconds")))
                since = now
            else:
                since = dt.datetime.fromisoformat(base[0])
            for p in u["programs"]:
                con.execute("INSERT OR IGNORE INTO addon_user_programs(user,image,first_seen) VALUES(?,?,?)",
                            (u["key"], p["image"].lower(), p["t"].isoformat(timespec="seconds")))
            rows = con.execute("SELECT image, first_seen FROM addon_user_programs WHERE user=? AND first_seen>=?",
                               (u["key"], (now - dt.timedelta(days=7)).isoformat(timespec="seconds"))).fetchall()
            cutoff = since + dt.timedelta(minutes=5)
            new_by_user[u["key"]] = {r[0]: r[1] for r in rows if dt.datetime.fromisoformat(r[1]) > cutoff}

    # ---- per-person analysis ---- #
    out_users, all_findings = [], []
    overall_heat = [[0] * 24 for _ in range(7)]
    week_ago = now - dt.timedelta(days=7)
    for u in users.values():
        s, fl = u["signins"], sorted(u["failed"], key=lambda r: r["t"])
        inter = [x for x in s if x["type"] in INTERACTIVE]
        heat = [[0] * 24 for _ in range(7)]
        for x in inter:
            heat[x["t"].weekday()][x["t"].hour] += 1
            overall_heat[x["t"].weekday()][x["t"].hour] += 1
        hist = collections.Counter(x["t"].hour for x in inter)
        odd_cells, odd = set(), []
        for x in inter:
            if x["t"] < week_ago:
                continue
            h = x["t"].hour
            if len(inter) >= 12:
                near = hist[h] + hist[(h - 1) % 24] + hist[(h + 1) % 24]
                rare = near <= max(1, len(inter) * 0.04)
            else:
                rare = h < 5
            if rare:
                odd.append(x)
                odd_cells.add((x["t"].weekday(), h))
        if odd:
            times = ", ".join(when(x["t"]) for x in odd[-5:])
            key = "odd_hours" if len(inter) >= 12 else "late_night"
            _finding(u, key, odd[-1]["t"], f"This account signed in at times it normally doesn't: {times}."
                     if key == "odd_hours" else f"This account signed in between midnight and 5 AM: {times}.",
                     {"count": len(odd)})
        # wrong-password bursts (5+ within 10 minutes)
        i = 0
        while i < len(fl):
            j = i
            while j + 1 < len(fl) and (fl[j + 1]["t"] - fl[i]["t"]).total_seconds() <= 600:
                j += 1
            n = j - i + 1
            if n >= 5:
                burst = fl[i:j + 1]
                srcs = sorted({b["ip"] or b["ws"] for b in burst if b["ip"] or b["ws"]})
                src = f" from {', '.join(srcs[:3])}" if srcs else ""
                end = burst[-1]["t"]
                ok = next((x for x in s if end <= x["t"] <= end + dt.timedelta(minutes=30)), None)
                if u.get("unknown"):
                    typed = sorted({b["typed"] for b in burst if b["typed"]})[:6]
                    _finding(u, "burst", end, f"{n} sign-in attempts used account names that don't exist on this PC{src} "
                                              f"({', '.join(typed) or 'blank'}), all within 10 minutes. This is what password-guessing tools do.")
                elif ok:
                    _finding(u, "burst_success", ok["t"], f"There were {n} wrong-password attempts{src} around {when(end)}, "
                                                           f"followed by a successful sign-in ({ok['how']}) at {when(ok['t'])}.")
                else:
                    _finding(u, "burst", end, f"There were {n} wrong-password attempts for this account{src} within 10 minutes, "
                                              f"ending {when(end)}. People rarely mistype that often.")
                i = j + 1
            else:
                i += 1
        # remote access
        ips = collections.OrderedDict()
        for x in s:
            if x["ip"]:
                r = ips.setdefault(x["ip"], {"ip": x["ip"], "kind": x["kind"], "count": 0, "last": None, "how": set()})
                r["count"] += 1
                r["last"] = x["t"]
                r["how"].add(x["how"])
        rdp = [x for x in s if x["type"] in REMOTE]
        for kind in ("internet", "local"):
            hits = [x for x in rdp if x["kind"] == kind] if kind == "internet" else [x for x in rdp if x["kind"] != "internet"]
            if hits:
                addrs = sorted({x["ip"] or "another device" for x in hits})
                _finding(u, "rdp_internet" if kind == "internet" else "rdp_local", hits[-1]["t"],
                         f"Signed in {len(hits)} time{'s' if len(hits) > 1 else ''} with Remote Desktop from "
                         f"{', '.join(addrs[:4])}. Last time: {when(hits[-1]['t'])}.", {"count": len(hits)})
        net_inet = [x for x in s if x["type"] not in REMOTE and x["kind"] == "internet"]
        if net_inet:
            _finding(u, "net_internet", net_inet[-1]["t"], f"Signed in over the network from internet address"
                     f"{'es' if len({x['ip'] for x in net_inet}) > 1 else ''} {', '.join(sorted({x['ip'] for x in net_inet})[:4])}.")
        # programs
        progs = u["programs"]
        pc = collections.Counter(p["image"].lower() for p in progs)
        names = {p["image"].lower(): p["image"] for p in progs}
        last_run = {p["image"].lower(): p["t"] for p in progs}
        newp = new_by_user.get(u["key"], {})
        risky = [k for k in pc if RISKY_DIR.search(k)]
        risky_new = [k for k in risky if k in newp]
        if risky_new:
            _finding(u, "risky_programs", max(last_run[k] for k in risky_new),
                     f"{len(risky_new)} program{'s' if len(risky_new) > 1 else ''} this person hadn't run before started from "
                     f"Downloads or a temporary folder: {', '.join(bn(names[k]) for k in risky_new[:5])}.")
        shells = collections.Counter()
        enc = []
        for p in progs:
            b = bn(p["image"]).lower()
            if b in SHELLS:
                shells[SHELLS[b]] += 1
                if "powershell" in b or "pwsh" in b:
                    if re.search(r"\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[a-z0-9+/=]{16,}", p["cmd"] or "", re.I):
                        if not M.is_self_noise(p["cmd"]) if hasattr(M, "is_self_noise") else True:
                            enc.append(p)
        if enc:
            par = sorted({bn(p["parent"]) for p in enc if p["parent"]})
            _finding(u, "encoded_ps", enc[-1]["t"], f"PowerShell ran a hidden (encoded) command {len(enc)} time{'s' if len(enc) > 1 else ''}"
                     + (f", started by {', '.join(par[:3])}." if par else "."))
        # result
        if not (s or fl or u["events"] or u["findings"] or progs):
            continue
        sevs = {f["sev"] for f in u["findings"]}
        status = "attention" if sevs & {"critical", "high"} else "unusual" if "medium" in sevs else "normal"
        timeline = ([{"t": x["t"], "kind": "warn" if x["type"] in REMOTE or x["kind"] == "internet" else "ok",
                      "text": "Signed in · " + x["how"] + (f" from {x['ip']}" if x["ip"] else "")} for x in s[-80:]]
                    + [{"t": x["t"], "kind": "bad", "text": f"{x['reason']}" + (f" ('{x['typed']}')" if u.get("unknown") else "")
                        + (f" from {x['ip'] or x['ws']}" if x["ip"] or x["ws"] else "")} for x in fl[-80:]] + u["events"])
        timeline.sort(key=lambda x: x["t"], reverse=True)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        u["findings"].sort(key=lambda f: f["when"] or "", reverse=True)
        u["findings"].sort(key=lambda f: sev_order[f["sev"]])
        all_findings += u["findings"]
        out_users.append({
            "key": u["key"], "name": u["name"], "display": u["display"], "domain": u["domain"], "admin": u["admin"],
            "unknown": bool(u.get("unknown")), "status": status,
            "signins": len(s), "failed": len(fl), "remote": len(rdp),
            "last_signin": s[-1]["t"].isoformat(timespec="seconds") if s else None,
            "first_signin": s[0]["t"].isoformat(timespec="seconds") if s else None,
            "active_days": len({x["t"].date() for x in s}),
            "methods": dict(collections.Counter(x["how"] for x in s).most_common()),
            "fail_reasons": dict(collections.Counter(x["reason"] for x in fl).most_common()),
            "ips": [{"ip": r["ip"], "kind": r["kind"], "count": r["count"], "last": r["last"].isoformat(timespec="seconds"),
                     "how": ", ".join(sorted(r["how"]))} for r in sorted(ips.values(), key=lambda r: -r["count"])][:30],
            "heat": heat, "odd_cells": sorted(odd_cells), "findings": u["findings"],
            "programs": {"started": len(progs), "distinct": len(pc),
                         "top": [{"name": bn(names[k]), "path": names[k], "count": c} for k, c in pc.most_common(8)],
                         "new": [{"name": bn(names[k]), "path": names[k], "first": v} for k, v in
                                 sorted(newp.items(), key=lambda kv: kv[1], reverse=True) if k in names][:25],
                         "risky": [{"name": bn(names[k]), "path": names[k], "count": pc[k],
                                    "last": last_run[k].isoformat(timespec="seconds"), "new": k in newp} for k in risky][:25],
                         "shells": dict(shells.most_common())},
            "timeline": [{"t": x["t"].isoformat(timespec="seconds"), "kind": x["kind"], "text": x["text"]} for x in timeline[:120]],
        })
    rank = {"attention": 0, "unusual": 1, "normal": 2}
    out_users.sort(key=lambda u: (rank[u["status"]], u["unknown"], -(dt.datetime.fromisoformat(u["last_signin"]).timestamp() if u["last_signin"] else 0)))
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda f: f["when"] or "", reverse=True)   # newest first...
    all_findings.sort(key=lambda f: sev_order[f["sev"]])              # ...within each severity
    real = [u for u in out_users if not u["unknown"]]
    if not sec and not notes:
        notes.append("No sign-in events were found for this period.")
    return {
        "generated": now.isoformat(timespec="seconds"), "days": days, "took": round(time.time() - t0, 1), "notes": notes,
        "summary": {"people": len(real), "attention": sum(1 for u in out_users if u["status"] == "attention"),
                    "unusual": sum(1 for u in out_users if u["status"] == "unusual"),
                    "signins": sum(u["signins"] for u in out_users), "failed": sum(u["failed"] for u in out_users),
                    "remote": sum(u["remote"] for u in out_users),
                    "odd_hours": sum(f.get("count", 1) for f in all_findings if f["key"] in ("odd_hours", "late_night")),
                    "new_programs": sum(len(u["programs"]["new"]) for u in out_users)},
        "heat": overall_heat, "findings": all_findings, "users": out_users,
    }


_REP = {"data": {}, "busy": set(), "err": {}, "lock": threading.Lock()}


def _build(days: int):
    try:
        data = build_report(days)
        with _REP["lock"]:
            _REP["data"][days] = (time.time(), data)
            _REP["err"].pop(days, None)
        _emit(data)
    except Exception as e:
        M.log.exception("user report")
        _REP["err"][days] = str(e)
    finally:
        _REP["busy"].discard(days)


def get_report(days: int, refresh: bool) -> dict:
    with _REP["lock"]:
        cached = _REP["data"].get(days)
        fresh = cached and time.time() - cached[0] < 300
        if (refresh or not fresh) and days not in _REP["busy"]:
            _REP["busy"].add(days)
            threading.Thread(target=_build, args=(days,), daemon=True).start()
        busy = days in _REP["busy"]
    return {"status": "building" if busy else "ready", "error": _REP["err"].get(days),
            "data": cached[1] if cached else None}


def _emit(data: dict):
    """Serious findings from the last 24 hours also appear on the Threats page."""
    cutoff = (dt.datetime.now() - dt.timedelta(hours=24)).isoformat(timespec="seconds")
    for f in data["findings"]:
        if f["sev"] in ("critical", "high") and f["when"] and f["when"] >= cutoff:
            uniq = "users|" + hashlib.sha1(f'{f["key"]}|{f["user"]}|{f["when"]}'.encode()).hexdigest()
            M.emit("users", f["sev"], f["title"], f["user_name"], details=f["what"], uniq=uniq, origin="schedule")


def _loop():
    time.sleep(90)
    while True:
        try:
            if not (hasattr(M, "is_paused") and M.is_paused()):
                _build(14)
        except Exception:
            M.log.exception("user report loop")
        time.sleep(1800)


def explain_users(e: dict) -> dict:
    key = TITLE_KEY.get(e["rule"])
    sev_title, sev_text = getattr(M, "SEV_TEXT", {}).get(e["severity"], ("", ""))
    _, title, steps, fp = F.get(key, ("", e["rule"], ["Open User activity for details."], ""))
    return {"severity": e["severity"], "level_title": sev_title, "level_text": sev_text, "program": "", "program_name": "",
            "rule": e["rule"], "title": title, "what": e.get("details") or "",
            "steps": steps + ["Open the User activity page for this person's full sign-in history."], "fp": fp,
            "running": [], "blocked": None, "protected_reason": "", "mute_match": "",
            "can": {"quarantine": False, "stop": False, "block": False, "firewall": False, "mute": True}}


# --------------------------------------------------------------------------- #
# Security checkup
# --------------------------------------------------------------------------- #
def _age_days(s):
    try:
        return (dt.datetime.now() - dt.datetime.fromisoformat(str(s).replace("Z", "")[:19])).total_seconds() / 86400
    except (ValueError, TypeError):
        return None


def checkup(refresh: bool = False) -> dict:
    checks = []

    def add(cid, group, state, title, text, fix=None, nist_func="Protect", nist_id=""):
        checks.append({"id": cid, "group": group, "state": state, "title": title, "text": text, "fix": fix,
                       "nist_function": nist_func, "nist_id": nist_id})

    # ---- OmniShield ---- #
    G = "OmniShield"
    pause = M.pause_state() if hasattr(M, "pause_state") else {"paused": False}
    if pause.get("paused"):
        add("paused", G, "bad", "Protection is paused", "Everything OmniShield does is switched off right now.",
            {"label": "Resume protection", "action": "resume"}, nist_func="Protect", nist_id="PR.PO")
    rt = bool(getattr(M, "RT", None) and M.RT.running)
    add("realtime", G, "ok" if rt else "warn", "Real-time protection",
        "On - new files and programs are checked within seconds." if rt else "Off - files are only checked when you scan.",
        None if rt else {"label": "Turn on", "action": "realtime"}, nist_func="Protect", nist_id="PR.PT-01")
    defs = M.defs_info() if hasattr(M, "defs_info") else {}
    age = defs.get("age_hours")
    add("defs", G, "warn" if age is None else "ok" if age <= 48 else "bad" if age > 168 else "warn", "Virus definitions",
        "Not downloaded yet." if age is None else f"Updated {int(age)} hours ago." if age < 48 else f"Last updated {int(age // 24)} days ago.",
        None if age is not None and age <= 48 else {"label": "Update now", "action": "defs"}, nist_func="Protect", nist_id="PR.IP-01")
    with M.db() as con:
        r = con.execute("SELECT finished FROM jobs WHERE kind='scan' AND state='done' AND target!='Protection self-test' "
                        "ORDER BY finished DESC LIMIT 1").fetchone()
        st = con.execute("SELECT result FROM jobs WHERE target='Protection self-test' AND state='done' ORDER BY finished DESC LIMIT 1").fetchone()
        hi = con.execute("SELECT COUNT(*) FROM events WHERE status='new' AND severity IN ('high','critical') AND engine!='console'").fetchone()[0]
    scan_age = _age_days(r[0]) if r else None
    add("scan", G, "ok" if scan_age is not None and scan_age <= 7 else "warn", "Recent scan",
        "No scan yet." if scan_age is None else f"Last scan {int(scan_age)} day{'s' if int(scan_age) != 1 else ''} ago." if scan_age >= 1 else "Scanned today.",
        None if scan_age is not None and scan_age <= 7 else {"label": "Quick scan", "action": "scan"}, nist_func="Detect", nist_id="DE.CM-01")
    try:
        test_ok = bool(st and json.loads(st[0] or "{}").get("self_test", {}).get("ok"))
    except ValueError:
        test_ok = False
    add("selftest", G, "ok" if test_ok else "warn", "Protection test",
        "Passed - a harmless test file was detected." if test_ok else "Not run yet. It takes about 10 seconds.",
        None if test_ok else {"label": "Run test", "action": "selftest"}, nist_func="Protect", nist_id="PR.IP-03")
    add("threats", G, "ok" if not hi else "bad", "Serious threats",
        "None waiting for you." if not hi else f"{hi} serious threat{'s' if hi > 1 else ''} waiting for you.",
        None if not hi else {"label": "Review", "action": "threats"}, nist_func="Respond", nist_id="RS.AN-01")
    if hasattr(M, "svc_state"):
        sm = M.svc_state(M.CFG["services"].get("sysmon", "Sysmon64"))
        add("sysmon", G, "ok" if sm == "running" else "warn" if sm == "unknown" else "bad", "Activity monitor (Sysmon)",
            "Running - records programs and network activity." if sm == "running" else "Not running - behavior checks see less.",
            None if sm in ("running", "unknown") else {"label": "Open Settings", "action": "go:settings"}, nist_func="Detect", nist_id="DE.CM-03")

    # ---- Windows ---- #
    W = "Windows"
    info = M.system_info(refresh) if hasattr(M, "system_info") else {}
    sec = (info or {}).get("security") or {}
    loc = local_info(refresh)
    if sec:
        on, rtp = sec.get("defender_on"), sec.get("defender_rt")
        add("defender", W, "ok" if on and rtp else "bad", "Microsoft Defender",
            "On, with real-time protection." if on and rtp else "Real-time protection is off." if on else "Turned off.",
            None if on and rtp else {"label": "Open Windows Security", "link": "windowsdefender://threatsettings"}, nist_func="Protect", nist_id="PR.PT-01")
        sa = _age_days(sec.get("defender_sigs"))
        if sa is not None:
            add("defender_sigs", W, "ok" if sa <= 3 else "warn", "Defender definitions",
                f"Updated {int(sa * 24)} hours ago." if sa < 2 else f"Updated {int(sa)} days ago.",
                None if sa <= 3 else {"label": "Check for updates", "link": "windowsdefender://threat"}, nist_func="Protect", nist_id="PR.IP-01")
        if sec.get("defender_tamper") is not None:
            add("tamper", W, "ok" if sec["defender_tamper"] else "warn", "Tamper protection",
                "On - malware can't switch Defender off." if sec["defender_tamper"] else "Off - malware could switch Defender off.",
                None if sec["defender_tamper"] else {"label": "Turn on", "link": "windowsdefender://threatsettings"}, nist_func="Protect", nist_id="PR.PT-01")
        fw = sec.get("firewall") or []
        fw = fw if isinstance(fw, list) else [fw]
        off = [f.get("name") for f in fw if not f.get("on")]
        if fw:
            add("firewall", W, "ok" if not off else "bad", "Windows Firewall",
                "On for all networks." if not off else f"Off for: {', '.join(off)}.",
                None if not off else {"label": "Open Firewall settings", "link": "windowsdefender://network"}, nist_func="Protect", nist_id="PR.AC-05")
        ua = _age_days(sec.get("last_update"))
        if ua is not None:
            add("updates", W, "ok" if ua <= 35 else "bad" if ua > 70 else "warn", "Windows Update",
                f"Last update installed {int(ua)} days ago." if ua >= 1 else "Updated today.",
                None if ua <= 35 else {"label": "Check for updates", "link": "ms-settings:windowsupdate"}, nist_func="Protect", nist_id="PR.IP-12")
        if sec.get("uac") is not None:
            add("uac", W, "ok" if sec["uac"] else "bad", "User Account Control",
                "On - Windows asks before programs make big changes." if sec["uac"] else "Off - programs can make big changes without asking.",
                None if sec["uac"] else {"label": "How to turn on", "link": "ms-settings:troubleshoot"}, nist_func="Protect", nist_id="PR.AC-04")
        if sec.get("bitlocker") is not None:
            b = str(sec["bitlocker"])
            add("bitlocker", W, "ok" if b == "On" else "warn", "Drive encryption (BitLocker)",
                "On - your files are protected if the PC is stolen." if b == "On" else "Off - anyone with the PC could read the drive.",
                None if b == "On" else {"label": "Open encryption settings", "link": "ms-settings:deviceencryption"}, nist_func="Protect", nist_id="PR.DS-01")
        if sec.get("secure_boot") is not None:
            add("secureboot", W, "ok" if sec["secure_boot"] else "warn", "Secure Boot",
                "On - blocks malware that loads before Windows." if sec["secure_boot"] else "Off - can only be turned on in the PC's BIOS/UEFI settings.",
                nist_func="Protect", nist_id="PR.PT-03")
    if loc:
        asr = loc.get("asr")
        if asr and isinstance(asr, dict) and asr.get("count", 0) > 0:
            blk = asr.get("block", 0)
            add("asr", W, "ok" if blk >= 10 else "warn", "Attack Surface Reduction (ASR)",
                f"{blk} rule{'s are' if blk != 1 else ' is'} blocking common malware/ransomware exploits." if blk > 0 else "ASR rules are installed but not in block mode.",
                {"label": "Manage Windows Security", "link": "windowsdefender://threatsettings"} if blk < 10 else None,
                nist_func="Protect", nist_id="PR.PT-02")
        elif asr is not None:
            add("asr", W, "warn", "Attack Surface Reduction (ASR)",
                "No ASR rules enabled. ASR blocks Office macro exploits, credential theft, and script-based malware.",
                {"label": "Enable ASR in Windows Security", "link": "windowsdefender://threatsettings"},
                nist_func="Protect", nist_id="PR.PT-02")
        if "rdp" in loc:
            add("rdp", W, "warn" if loc["rdp"] else "ok", "Remote Desktop",
                "On - other computers can sign in to this PC. Turn it off if you don't use it." if loc["rdp"] else "Off.",
                {"label": "Open Remote Desktop settings", "link": "ms-settings:remotedesktop"} if loc["rdp"] else None,
                nist_func="Protect", nist_id="PR.AC-03")
        if "guest" in loc:
            add("guest", W, "bad" if loc["guest"] else "ok", "Guest account",
                "On - anyone can use this PC without a password." if loc["guest"] else "Off.",
                {"label": "Open accounts", "link": "ms-settings:otherusers"} if loc["guest"] else None,
                nist_func="Identify", nist_id="ID.AM-01")
        admins = [a for a in (loc.get("admins") or []) if not a.lower().endswith("\\administrator")]
        if admins:
            add("admins", W, "ok" if len(admins) <= 2 else "warn", "Administrator accounts",
                f"{len(admins)} account{'s' if len(admins) > 1 else ''} with full control: {', '.join(a.split(chr(92))[-1] for a in admins[:5])}.",
                None if len(admins) <= 2 else {"label": "Review accounts", "link": "ms-settings:otherusers"},
                nist_func="Identify", nist_id="ID.AM-01")
        nop = loc.get("nopass") or []
        if nop:
            add("nopass", W, "bad", "Accounts without a password", f"These accounts can sign in without a password: {', '.join(nop[:5])}.",
                {"label": "Open accounts", "link": "ms-settings:otherusers"},
                nist_func="Protect", nist_id="PR.AC-01")
        if loc.get("autologon"):
            add("autologon", W, "warn", "Automatic sign-in", "Windows signs in by itself when it starts, so anyone who turns the PC on gets in.",
                nist_func="Protect", nist_id="PR.AC-01")
        if loc.get("smb1"):
            add("smb1", W, "bad", "Old file-sharing protocol (SMBv1)", "SMBv1 is on. It's outdated and was used by ransomware like WannaCry.",
                {"label": "Open Windows features", "link": "ms-settings:optionalfeatures"},
                nist_func="Protect", nist_id="PR.PT-04")
    ok = sum(1 for c in checks if c["state"] == "ok")
    order = {"bad": 0, "warn": 1, "ok": 2}
    checks.sort(key=lambda c: (c["group"] != "OmniShield", order[c["state"]]))

    nist_summary = {}
    for fn in ("Identify", "Protect", "Detect", "Respond", "Recover"):
        fn_checks = [c for c in checks if c.get("nist_function") == fn]
        if fn_checks:
            fn_ok = sum(1 for c in fn_checks if c["state"] == "ok")
            nist_summary[fn] = {
                "total": len(fn_checks),
                "ok": fn_ok,
                "warn": sum(1 for c in fn_checks if c["state"] == "warn"),
                "bad": sum(1 for c in fn_checks if c["state"] == "bad"),
                "score": round(fn_ok * 100 / max(1, len(fn_checks)))
            }

    return {"checks": checks, "ok": ok, "total": len(checks), "score": round(ok * 100 / max(1, len(checks))),
            "bad": sum(1 for c in checks if c["state"] == "bad"), "warn": sum(1 for c in checks if c["state"] == "warn"),
            "time": dt.datetime.now().isoformat(timespec="seconds"), "windows_details": bool(sec),
            "nist_summary": nist_summary}


_CHK = {"data": None, "t": 0.0, "lock": threading.Lock()}


def get_checkup(refresh: bool) -> dict:
    with _CHK["lock"]:
        if refresh or _CHK["data"] is None or time.time() - _CHK["t"] > 120:
            _CHK["data"], _CHK["t"] = checkup(refresh), time.time()
        return _CHK["data"]


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #
def api_report(days: int = 14, refresh: bool = False):
    if days not in (1, 7, 14, 30):
        raise HTTPException(400, "days must be 1, 7, 14 or 30")
    return get_report(days, refresh)


def api_checkup(refresh: bool = False):
    try:
        return get_checkup(refresh)
    except Exception as e:
        M.log.exception("checkup")
        raise HTTPException(500, str(e))


def register(app, main):
    global M
    M = main
    try:
        M.VERSION = "1.8"
        with M._db_lock, M.db() as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS addon_user_programs(user TEXT, image TEXT, first_seen TEXT, PRIMARY KEY(user, image));
            CREATE TABLE IF NOT EXISTS addon_user_baseline(user TEXT PRIMARY KEY, since TEXT);
            """)
        app.add_api_route("/api/users/report", api_report, methods=["GET"])
        app.add_api_route("/api/checkup", api_checkup, methods=["GET"])
        orig = M.explain_event
        M.explain_event = lambda e: explain_users(e) if e.get("engine") == "users" else orig(e)
        threading.Thread(target=_loop, daemon=True, name="addon-users").start()
        M.log.info("Add-on 1.8 loaded (User activity, Security checkup)")
    except Exception:
        M.log.exception("Add-on registration failed")
    try:
        import addon_vt
        addon_vt.register(app, main)
    except Exception:
        M.log.exception("VirusTotal add-on failed to load")
