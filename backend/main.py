"""
Security Console - Pure Windows backend
Orchestrates ClamAV, YARA, osquery, Hayabusa (Sigma) and Sysmon, stores every
result in one SQLite database and serves the web UI on http://127.0.0.1:8080

v1.4: settings from the UI, stop/block programs, block internet access,
      mute alerts, plain-English threat explanations, self-test.
"""
import collections
import datetime as dt
import hashlib
import json
import logging
import os
import pathlib
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET

import ctypes
import math
from ctypes import wintypes

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

try:
    import psutil  # process control (stop / block programs)
except Exception:  # pragma: no cover
    psutil = None
try:
    import win32evtlog  # type: ignore  # Windows event log API (pywin32)
except Exception:  # pragma: no cover
    win32evtlog = None
try:
    from watchdog.events import FileSystemEventHandler  # type: ignore
    from watchdog.observers import Observer  # type: ignore
except Exception:  # pragma: no cover
    FileSystemEventHandler, Observer = object, None

VERSION = "1.7"

# --------------------------------------------------------------------------- #
# Paths & configuration
# --------------------------------------------------------------------------- #
BASE = pathlib.Path(os.environ.get("SC_HOME", r"C:\SecurityConsole"))
CFG_FILE = BASE / "config" / "console.json"

DEFAULT_CFG = {
    "host": "127.0.0.1",
    "port": 8080,
    "clamdscan": r"C:\Program Files\ClamAV\clamdscan.exe",
    "clamscan": r"C:\Program Files\ClamAV\clamscan.exe",
    "clamd_host": "127.0.0.1",
    "clamd_port": 3310,
    "yara": str(BASE / "tools" / "yara" / "yara64.exe"),
    "yarac": str(BASE / "tools" / "yara" / "yarac64.exe"),
    "yara_rules": str(BASE / "rules" / "yara" / "index.yar"),
    "osqueryi": r"C:\Program Files\osquery\osqueryi.exe",
    "hayabusa": str(BASE / "tools" / "hayabusa" / "hayabusa.exe"),
    "quarantine": str(BASE / "quarantine"),
    "services": {"clamav": "ClamD", "freshclam": "FreshClam", "osquery": "osqueryd", "sysmon": "Sysmon64"},
    # ---- everything below can be changed from the Settings page ----
    "sigma_min_level": "medium",
    "sigma_include_experimental": False,
    "sigma_every": 15,                # minutes, 0 = off
    "hunts_every": 60,                # minutes, 0 = off
    "daily_scan_enabled": True,
    "daily_scan_time": "12:30",
    "daily_scan_scope": "quick",      # quick | full
    "daily_scan_action": "report",    # report | quarantine
    "max_file_mb": 512,
    "history_days": 90,               # 0 = keep forever
    "rt_auto_stop": False,
    "rt_scan_process_memory": False,
    "rt_sigma_seconds": 60,
    "rt_max_file_mb": 150,
    "rt_extra_folders": [],
    "hide_self": True,                # don't alert about Security Console's own activity
    # ---- advanced ----
    "scan_batch": 300,
    "rt_settle_seconds": 1.5,
    "rt_channels": [
        "Security", "System",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational",
        "Windows PowerShell",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-Bits-Client/Operational",
    ],
}

# Settings that the UI may change, with validation
SETTINGS_SCHEMA = {
    "sigma_min_level": ("choice", ["low", "medium", "high", "critical"]),
    "sigma_include_experimental": ("bool",),
    "sigma_every": ("choice", [0, 15, 30, 60, 180]),
    "hunts_every": ("choice", [0, 60, 360, 1440]),
    "daily_scan_enabled": ("bool",),
    "daily_scan_time": ("time",),
    "daily_scan_scope": ("choice", ["quick", "full"]),
    "daily_scan_action": ("choice", ["report", "quarantine"]),
    "max_file_mb": ("int", 10, 4096),
    "history_days": ("choice", [30, 90, 365, 0]),
    "rt_auto_stop": ("bool",),
    "rt_scan_process_memory": ("bool",),
    "rt_sigma_seconds": ("choice", [30, 60, 120, 300]),
    "rt_max_file_mb": ("int", 10, 2048),
    "rt_extra_folders": ("folders",),
    "hide_self": ("bool",),
}


def load_cfg() -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CFG))
    if CFG_FILE.exists():
        try:
            cfg.update(json.loads(CFG_FILE.read_text(encoding="utf-8-sig")))
        except Exception as e:
            logging.error("Config error, using defaults: %s", e)
    return cfg


CFG = load_cfg()
DB = BASE / "data" / "console.db"
for d in (DB.parent, BASE / "logs", pathlib.Path(CFG["quarantine"])):
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(filename=BASE / "logs" / "backend.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sc")
NO_WINDOW = 0x08000000 if os.name == "nt" else 0


OWN_PIDS: "collections.OrderedDict[int, float]" = collections.OrderedDict()


def remember_pid(pid: int):
    """Programs Security Console starts itself - their activity in Windows logs isn't a threat."""
    OWN_PIDS[pid] = time.time()
    OWN_PIDS.move_to_end(pid)
    while len(OWN_PIDS) > 5000:
        OWN_PIDS.popitem(last=False)


remember_pid(os.getpid())


def run(cmd: list, timeout: int = 3600, cwd: str | None = None) -> subprocess.CompletedProcess:
    log.info("exec: %s", cmd)
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd,
                          encoding="utf-8", errors="replace", creationflags=NO_WINDOW) as p:
        remember_pid(p.pid)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            raise
    return subprocess.CompletedProcess(cmd, p.returncode, out, err)


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY, time TEXT, engine TEXT, severity TEXT, rule TEXT, target TEXT,
    details TEXT, uniq TEXT UNIQUE, status TEXT DEFAULT 'new', origin TEXT DEFAULT '',
    mitre_attack TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_events_time ON events(time);
CREATE TABLE IF NOT EXISTS jobs(
    id TEXT PRIMARY KEY, kind TEXT, target TEXT, state TEXT, started TEXT, finished TEXT,
    result TEXT, progress TEXT);
CREATE TABLE IF NOT EXISTS baseline(hunt TEXT, rowhash TEXT, first_seen TEXT, PRIMARY KEY(hunt,rowhash));
CREATE TABLE IF NOT EXISTS quarantine(id INTEGER PRIMARY KEY, original TEXT, stored TEXT, sha256 TEXT, time TEXT);
CREATE TABLE IF NOT EXISTS exclusions(id INTEGER PRIMARY KEY, kind TEXT, value TEXT, note TEXT, created TEXT, UNIQUE(kind, value));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS blocked(id INTEGER PRIMARY KEY, path TEXT UNIQUE, name TEXT, sha256 TEXT,
    firewall INTEGER DEFAULT 0, run_block INTEGER DEFAULT 1, note TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS mutes(id INTEGER PRIMARY KEY, engine TEXT, rule TEXT, match TEXT, note TEXT, created TEXT,
    UNIQUE(engine, rule, match));
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY, applied_at TEXT);
"""
_db_lock = threading.Lock()


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=NORMAL;")
        con.execute("PRAGMA busy_timeout=5000;")
    except sqlite3.OperationalError:
        pass
    return con


def now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


with db() as _c:
    _c.executescript(SCHEMA)
    for tbl, col, ddl in (("jobs", "progress", "TEXT"), ("events", "origin", "TEXT DEFAULT ''"), ("events", "mitre_attack", "TEXT DEFAULT ''")):
        if col not in [r[1] for r in _c.execute(f"PRAGMA table_info({tbl})")]:
            _c.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {ddl}")
    _c.execute("INSERT OR IGNORE INTO schema_version(version, applied_at) VALUES(2, ?)", (now(),))
    _c.execute("UPDATE jobs SET state='error', finished=?, result=? WHERE state='running'",
               (now(), json.dumps({"error": "Interrupted (Security Console restarted)"})))


def get_setting(key: str, default: str = "") -> str:
    with db() as con:
        r = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(key: str, value: str):
    with _db_lock, db() as con:
        con.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, value))


# Settings changed in the UI are stored in the database and win over console.json
try:
    CFG.update({k: v for k, v in json.loads(get_setting("config", "{}")).items() if k in SETTINGS_SCHEMA})
except ValueError:
    pass


# ---- MITRE ATT&CK Mapping -------------------------------------------------- #
MITRE_KEYWORDS = [
    (("lsass", "mimikatz", "credential", "password", "sam database", "dump", "secretsdump", "kerberos", "ntds", "infostealer", "keylogger"), "T1003 - OS Credential Dumping (Credential Access)"),
    (("defender", "antivirus", "tamper", "disable security", "exclusion", "amsi"), "T1562.001 - Impair Defenses: Disable Tools (Defense Evasion)"),
    (("ransom", "shadow cop", "vssadmin", "wbadmin", "bcdedit", "encrypt"), "T1486 - Data Encrypted for Impact (Impact)"),
    (("clear", "wevtutil", "log deleted", "audit policy", "eventlog"), "T1070.001 - Clear Windows Event Logs (Defense Evasion)"),
    (("powershell", "pwsh", "encoded", "-enc", "iex", "invoke-expression", "downloadstring", "scriptblock"), "T1059.001 - PowerShell (Execution)"),
    (("cmd.exe", "command prompt", "batch"), "T1059.003 - Windows Command Shell (Execution)"),
    (("wscript", "cscript", "vbs", "js", "mshta"), "T1059.005 - Visual Basic / Scripts (Execution)"),
    (("wmi", "wsman", "winrm", "remote management", "com object", "dcom", "comhijack"), "T1047 - WMI (Execution)"),
    (("scheduled task", "schtasks", "task scheduler", "at.exe"), "T1053.005 - Scheduled Task (Persistence)"),
    (("service", "sc.exe", "new service"), "T1543.003 - Windows Service (Persistence)"),
    (("run key", "autorun", "startup", "registry", "reg.exe", "winlogon", "userinit"), "T1547.001 - Registry Run Keys (Persistence)"),
    (("user", "account", "admin", "group", "net.exe", "net1"), "T1136 - Create Account (Persistence)"),
    (("rundll32", "regsvr32", "mshta", "msiexec", "installutil", "lolbin", "lolbas"), "T1218 - System Binary Proxy Execution (Defense Evasion)"),
    (("uac", "bypass", "elevat", "privilege", "token"), "T1548.002 - Bypass User Account Control (Privilege Escalation)"),
    (("certutil", "bitsadmin", "download", "curl", "wget", "invoke-webrequest", "downloader", "dropper"), "T1105 - Ingress Tool Transfer (Command and Control)"),
    (("office", "winword", "excel", "outlook", "macro", "powerpnt"), "T1204.002 - Malicious File (Initial Access)"),
    (("logon", "login", "brute", "failed", "rdp", "remote desktop", "authentication"), "T1110 - Brute Force (Credential Access)"),
    (("network", "connection", "dns", "proxy", "tunnel", "tor"), "T1071 - Application Layer Protocol (Command and Control)"),
    (("webshell", "c99", "r57", "b374k"), "T1505.003 - Web Shell (Persistence)"),
]


def map_mitre(engine: str, rule: str, text: str) -> str:
    hay = f"{rule} {text}".lower()
    for keys, technique in MITRE_KEYWORDS:
        if any(k in hay for k in keys):
            return technique
    if engine == "clamav":
        return "T1204.002 - User Execution: Malicious File (Execution)"
    if engine == "yara":
        return "T1027 - Obfuscated Files or Information (Defense Evasion)"
    return ""


# ---- muted alerts ---------------------------------------------------------- #
_MUTES = {"rows": None}


def mutes() -> list[dict]:
    if _MUTES["rows"] is None:
        with db() as con:
            _MUTES["rows"] = [dict(r) for r in con.execute("SELECT * FROM mutes")]
    return _MUTES["rows"]


def is_muted(engine: str, rule: str, text: str) -> bool:
    t = (text or "").lower()
    for m in mutes():
        if m["rule"] == rule and m["engine"] in ("", engine) and (not m["match"] or m["match"].lower() in t):
            return True
    return False


def emit(engine, severity, rule, target, details="", uniq=None, origin="", mitre="") -> dict | None:
    """Store one normalized event. `uniq` de-duplicates repeated findings."""
    if is_muted(engine, rule, f"{target} {details}"):
        return None
    uniq = uniq or hashlib.sha1(f"{engine}|{rule}|{target}|{now()}".encode()).hexdigest()
    mitre_val = mitre or map_mitre(engine, rule, f"{target} {details}")
    ev = dict(time=now(), engine=engine, severity=severity, rule=rule, target=target,
              details=details, uniq=uniq, origin=origin, mitre_attack=mitre_val)
    with _db_lock, db() as con:
        cur = con.execute("INSERT OR IGNORE INTO events(time,engine,severity,rule,target,details,uniq,origin,mitre_attack)"
                          " VALUES(:time,:engine,:severity,:rule,:target,:details,:uniq,:origin,:mitre_attack)", ev)
        if cur.rowcount == 0:
            return None
        ev["id"] = cur.lastrowid
    log.info("event %s %s %s %s %s [%s]", origin or "-", engine, severity, rule, target, mitre_val)
    return ev


# --------------------------------------------------------------------------- #
# Self-noise filter: Security Console's own activity is never a threat
# --------------------------------------------------------------------------- #
PID_RE = re.compile(r"\b(?:PID|ParentPID|ProcessId|ParentProcessId|SrcPID|SourceProcessId)\s*[:=]\s*(\d+)", re.I)
OWN_NAMES = ("sysmon64", "sysmondrv", "clamd", "freshclam", "osqueryd", "nssm.exe")


def self_markers() -> set[str]:
    port = str(CFG.get("port", 8080))
    m = {str(BASE).lower(), f"127.0.0.1:{port}", f"localhost:{port}", "securityconsole", "security console", "sc-internal"}
    m.update(d.lower() for d in own_dirs())
    return {x for x in m if len(x) > 3}


def is_self_noise(text: str) -> bool:
    if not CFG.get("hide_self", True) or not text:
        return False
    t = text.lower()
    if any(mk in t for mk in self_markers()):
        return True
    cutoff = time.time() - 6 * 3600
    return any(OWN_PIDS.get(int(p), 0) > cutoff for p in PID_RE.findall(text))


def is_self_row(row: dict) -> bool:
    if not CFG.get("hide_self", True):
        return False
    text = " ".join(str(v) for v in row.values()).lower()
    return is_self_noise(text) or any(n in text for n in OWN_NAMES)


def hide_self_alerts() -> int:
    """Hide alerts that Security Console's own activity caused (also tidies up older versions' alerts)."""
    if not CFG.get("hide_self", True):
        return 0
    with db() as con:
        rows = con.execute("SELECT id,engine,target,details FROM events WHERE status='new' "
                           "AND engine IN ('sigma','osquery')").fetchall()
    ids = []
    for r in rows:
        hit = is_self_noise(f'{r["target"]} {r["details"]}')
        if not hit and r["engine"] == "osquery":
            try:
                hit = is_self_row(json.loads(r["details"] or "{}"))
            except ValueError:
                pass
        if hit:
            ids.append(r["id"])
    if ids:
        with _db_lock, db() as con:
            con.executemany("UPDATE events SET status='ack' WHERE id=?", [(i,) for i in ids])
        log.info("hid %d alerts caused by Security Console itself", len(ids))
    return len(ids)


# --------------------------------------------------------------------------- #
# Engines
# --------------------------------------------------------------------------- #
def svc_state(name: str) -> str:
    if os.name != "nt":
        return "unknown"
    try:
        out = run(["sc", "query", name], timeout=10).stdout
    except Exception:
        return "unknown"
    if "RUNNING" in out:
        return "running"
    if "STOPPED" in out:
        return "stopped"
    return "not installed"


def osquery(sql: str) -> list:
    if not pathlib.Path(CFG["osqueryi"]).exists():
        raise RuntimeError("osqueryi.exe not found")
    r = run([CFG["osqueryi"], "--json", sql], timeout=300)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "osquery error")
    return json.loads(r.stdout or "[]")


def sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


# ---- Hayabusa (Sigma): 4.x "dfir-timeline -t jsonl", older "json-timeline -L" -- #
SIGMA_LEVEL = {"crit": "critical", "critical": "critical", "emer": "critical", "emergency": "critical",
               "high": "high", "med": "medium", "medium": "medium", "low": "low", "info": "low", "informational": "low"}
_HB = {"mode": None}
_HB_LOCK = threading.Lock()


def hayabusa_timeline(input_args: list, out: pathlib.Path, timeout: int = 3600):
    exe = pathlib.Path(CFG["hayabusa"])
    if not exe.exists():
        raise RuntimeError("hayabusa.exe not found")
    status = "deprecated,unsupported" if CFG.get("sigma_include_experimental") else "deprecated,unsupported,experimental"
    common = ["-w", "-q", "-C", "-m", CFG.get("sigma_min_level", "medium"), "--exclude-status", status]
    modes = [_HB["mode"]] if _HB["mode"] else ["dfir", "legacy"]
    last = None
    for mode in modes:
        sub = ["dfir-timeline", "-t", "jsonl"] if mode == "dfir" else ["json-timeline", "-L"]
        out.unlink(missing_ok=True)
        r = run([str(exe)] + sub + input_args + common + ["-o", str(out)], timeout=timeout, cwd=str(exe.parent))
        if out.exists() or r.returncode == 0:
            _HB["mode"] = mode
            return
        last = r
    msg = ((last.stderr or "") + (last.stdout or "")).strip() if last else ""
    raise RuntimeError("Hayabusa failed: " + (msg[-400:] or "no output"))


def _hb_details(v) -> str:
    if isinstance(v, dict):
        return " | ".join(f"{k}: {x}" for k, x in v.items())
    return str(v or "")


def ingest_hayabusa(out: pathlib.Path, origin: str = "") -> int:
    if not out.exists():
        return 0
    new = 0
    with out.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            details = _hb_details(row.get("Details")) or _hb_details(row.get("ExtraFieldInfo"))
            if is_self_noise(f'{_hb_details(row.get("Details"))} {_hb_details(row.get("ExtraFieldInfo"))}'):
                continue  # caused by Security Console itself
            rule = row.get("RuleTitle", "Sigma rule")
            ts = row.get("Timestamp", "")
            target = f'{row.get("Computer", "")} / {row.get("Channel", "")} / EID {row.get("EventID", "")}'
            sev = SIGMA_LEVEL.get(str(row.get("Level", "")).lower(), "medium")
            key = f'{ts}|{rule}|{row.get("Computer", "")}|{row.get("Channel", "")}|{row.get("EventID", "")}|{row.get("RecordID", "")}'
            mitre = ""
            ma = row.get("MitreAttack")
            if isinstance(ma, list):
                mitre = ", ".join(str(x) for x in ma if x)
            elif isinstance(ma, str):
                mitre = ma.strip()
            if not mitre:
                tags = row.get("Tags") or []
                if isinstance(tags, str):
                    tags = tags.split()
                attack_tags = [str(t).replace("attack.", "").upper() for t in tags if "attack." in str(t).lower()]
                if attack_tags:
                    mitre = ", ".join(attack_tags)
            if emit("sigma", sev, rule, target, details=f"{ts} {details}",
                    uniq="sigma|" + hashlib.sha1(key.encode()).hexdigest(), origin=origin, mitre=mitre):
                new += 1
    return new


def run_sigma() -> int:
    out = BASE / "data" / "hayabusa.jsonl"
    with _HB_LOCK:
        hayabusa_timeline(["-l"], out, timeout=3600)
        return ingest_hayabusa(out, origin="schedule")


# --------------------------------------------------------------------------- #
# File scanner (report only by default)
# --------------------------------------------------------------------------- #
JOB_CANCEL: set[str] = set()
ALWAYS_SKIP_NAMES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp"}


def norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.expandvars(str(p).strip().strip('"'))))


def canonical_path(p: str) -> str:
    """Canonicalize paths to prevent symlink, junction, and 8.3 short name traversal bypasses."""
    if not p:
        return ""
    n = norm(p)
    try:
        if os.path.exists(n):
            return os.path.normcase(os.path.realpath(n))
    except Exception:
        pass
    return n


def under(path: str, folder: str) -> bool:
    n, f = canonical_path(path), canonical_path(folder).rstrip("\\/")
    return n == f or n.startswith(f + os.sep)


def builtin_exclusions() -> list[dict]:
    items = [(str(BASE), "Security Console's own files, rules and logs"),
             (CFG["quarantine"], "Quarantined files are already locked away"),
             (str(pathlib.Path(CFG["clamscan"]).parent), "ClamAV program and virus database")]
    if os.name == "nt":
        items.append((os.path.expandvars(r"%SystemDrive%\System Volume Information"), "Windows restore data (not readable)"))
    seen, out = set(), []
    for p, why in items:
        if norm(p) not in seen:
            seen.add(norm(p))
            out.append({"value": p, "why": why})
    return out


def list_exclusions() -> list[dict]:
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM exclusions ORDER BY id DESC")]


class Exclusions:
    """use_rules=False is used by 'Is this safe?' - it checks everything you pick."""

    def __init__(self, use_rules: bool = True):
        if use_rules:
            rows = list_exclusions()
            paths = [b["value"] for b in builtin_exclusions()] + [r["value"] for r in rows if r["kind"] == "path"]
            self.exts = {r["value"].lower() for r in rows if r["kind"] == "ext"}
        else:
            paths, self.exts = [CFG["quarantine"]], set()
        self.paths = [norm(p).rstrip("\\/") for p in paths]

    def path(self, p: str) -> bool:
        n = norm(p)
        return any(n == e or n.startswith(e + os.sep) for e in self.paths)

    def file(self, p: str) -> bool:
        name = os.path.basename(p).lower()
        return name in ALWAYS_SKIP_NAMES or os.path.splitext(name)[1] in self.exts or self.path(p)


def walk(root: str, ex: Exclusions, stats: dict, cancelled, max_mb: int):
    max_bytes = int(max_mb) * 1024 * 1024
    if os.path.isfile(root):
        if ex.file(root):
            stats["excluded"] += 1
        else:
            yield root
        return
    if ex.path(root):
        stats["excluded"] += 1
        return
    stack = [root]
    while stack:
        if cancelled():
            return
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            stats["unreadable"] += 1
            continue
        with it:
            for e in it:
                try:
                    if e.is_symlink() or (hasattr(e, "is_junction") and e.is_junction()):
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if ex.path(e.path):
                            stats["excluded"] += 1
                        else:
                            stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        if ex.file(e.path):
                            stats["excluded"] += 1
                        elif e.stat(follow_symlinks=False).st_size > max_bytes:
                            stats["too_big"] += 1
                        else:
                            yield e.path
                except OSError:
                    stats["unreadable"] += 1


CLAM_CATEGORY = {
    "ransomware": ("dangerous", "critical", "Ransomware: can encrypt your files and demand payment to unlock them."),
    "trojan": ("dangerous", "high", "Trojan: pretends to be harmless but can steal data or give attackers access."),
    "backdoor": ("dangerous", "high", "Backdoor: can let an attacker control this PC remotely."),
    "downloader": ("dangerous", "high", "Downloader: fetches and installs other malware from the internet."),
    "dropper": ("dangerous", "high", "Dropper: carries hidden malware and installs it."),
    "worm": ("dangerous", "high", "Worm: copies itself to other files or computers."),
    "virus": ("dangerous", "high", "Virus: infects other files on the PC."),
    "exploit": ("dangerous", "high", "Exploit: abuses a software weakness to break into the system."),
    "keylogger": ("dangerous", "high", "Keylogger: records what you type, including passwords."),
    "spyware": ("dangerous", "high", "Spyware: secretly collects information about you."),
    "infostealer": ("dangerous", "high", "Info-stealer: steals saved passwords, cookies or other data."),
    "coinminer": ("dangerous", "high", "Coin miner: secretly uses your PC to mine cryptocurrency."),
    "phishing": ("dangerous", "high", "Phishing: a fake document or page made to steal logins."),
    "malware": ("dangerous", "high", "Malware: known malicious software."),
    "packed": ("suspicious", "medium", "Packed: the program is disguised or compressed in a way malware often uses."),
    "adware": ("suspicious", "medium", "Adware: shows unwanted ads or changes browser settings."),
    "tool": ("suspicious", "medium", "Hacking tool: a real admin or security tool that attackers often misuse."),
    "test": ("suspicious", "low", "Test file: a harmless file made to check that antivirus works."),
}
CLAM_PLATFORM = {"win": "Windows programs", "doc": "Office documents", "xls": "Excel files", "pdf": "PDF files",
                 "html": "web pages", "js": "JavaScript", "email": "email files", "andr": "Android apps",
                 "unix": "Linux/Unix", "osx": "macOS", "multios": "several systems", "txt": "text/scripts",
                 "java": "Java", "swf": "Flash", "img": "images", "rtf": "RTF documents"}


def explain_clamav(sig: str) -> dict:
    parts = sig.split(".")
    head = parts[0].lower()
    if head == "pua":
        return dict(level="suspicious", severity="medium",
                    what="Potentially unwanted app: not proven malware, but often bundled, unwanted or risky.")
    if head == "heuristics":
        sub = (parts[1] if len(parts) > 1 else "").lower()
        if sub == "encrypted":
            return dict(level="suspicious", severity="medium",
                        what="Password-protected archive: its contents couldn't be checked. Only open it if you trust the sender.")
        if sub == "phishing":
            return dict(level="dangerous", severity="high", what=CLAM_CATEGORY["phishing"][2])
        if sub == "broken":
            return dict(level="suspicious", severity="medium",
                        what="Damaged program file: broken executables are sometimes used to hide malware.")
        return dict(level="suspicious", severity="medium",
                    what="Looks like malware based on its behavior or structure, but isn't a known sample.")
    cat = (parts[1] if len(parts) > 1 else "").lower()
    level, sev, what = CLAM_CATEGORY.get(cat, ("dangerous", "high", "Known malicious file."))
    plat = CLAM_PLATFORM.get(head)
    if plat and cat != "test":
        what += f" Targets {plat}."
    return dict(level=level, severity=sev, what=what)


def explain_yara(rule: str, meta: dict) -> dict:
    sev = str(meta.get("severity", "high")).lower()
    if sev not in ("critical", "high", "medium", "low"):
        sev = "high"
    level = "dangerous" if sev in ("critical", "high") else "suspicious"
    return dict(level=level, severity=sev, what=meta.get("description") or f'Matches the pattern rule "{rule}".',
                mitre=meta.get("mitre", ""))


YARA_LINE = re.compile(r"^(\S+) \[(.*)\] ((?:[A-Za-z]:[\\/]|\\\\|/).*)$")
YARA_META = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^,]+)')


def parse_yara_line(line: str):
    m = YARA_LINE.match(line)
    if m:
        rule, meta_s, path = m.groups()
        meta = {k: v[1:-1].replace('\\"', '"') if v.startswith('"') else v for k, v in YARA_META.findall(meta_s)}
        return rule, meta, path
    if " " in line:
        rule, path = line.split(" ", 1)
        return rule, {}, path
    return None


def clamav_batch(list_file: str, daemon: bool) -> tuple[list, int]:
    exe = CFG["clamdscan"] if daemon else CFG["clamscan"]
    r = run([exe, "--no-summary", "--infected", f"--file-list={list_file}"], timeout=6 * 3600)
    hits, errors = [], 0
    for line in r.stdout.splitlines():
        if line.endswith(" FOUND") and ": " in line:
            path, sig = line.rsplit(": ", 1)
            hits.append((path, sig[:-6]))
        elif line.endswith(" ERROR"):
            errors += 1
    return hits, errors


def yara_batch(list_file: str, rules: str, compiled: bool) -> tuple[list, int]:
    args = [CFG["yara"], "-w", "-m", "-a", "60"] + (["-C"] if compiled else [])
    r = run(args + ["--scan-list", rules, list_file], timeout=6 * 3600)
    hits = [h for h in (parse_yara_line(l) for l in r.stdout.splitlines()) if h]
    return hits, sum(1 for l in r.stderr.splitlines() if l.strip())


def prepare_yara(out_name: str = "rules.yarc") -> tuple[str, bool] | None:
    if not pathlib.Path(CFG["yara"]).exists() or not pathlib.Path(CFG["yara_rules"]).exists():
        return None
    yarac = pathlib.Path(CFG.get("yarac") or pathlib.Path(CFG["yara"]).with_name("yarac64.exe"))
    if yarac.exists():
        out = BASE / "data" / out_name
        r = run([str(yarac), "-w", CFG["yara_rules"], str(out)], timeout=600)
        if r.returncode == 0 and out.exists():
            return str(out), True
        log.warning("yarac failed, using source rules: %s", r.stderr[:300])
    return CFG["yara_rules"], False


def clamav_mode() -> str | None:
    if svc_state(CFG["services"]["clamav"]) == "running" and pathlib.Path(CFG["clamdscan"]).exists():
        return "daemon"
    if os.name == "nt" and svc_state(CFG["services"]["clamav"]) == "stopped":
        run(["sc", "start", CFG["services"]["clamav"]], timeout=30)
        time.sleep(8)
        if svc_state(CFG["services"]["clamav"]) == "running":
            return "daemon"
    return "standalone" if pathlib.Path(CFG["clamscan"]).exists() else None


# ---- clamd network client --------------------------------------------------- #
def _clamd_recv(s: socket.socket) -> str:
    buf = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
        if buf.endswith(b"\0"):
            break
    return buf.rstrip(b"\0").decode("utf-8", "replace").strip()


def _clamd_parse(resp: str) -> tuple[str, str]:
    if resp.endswith(" FOUND"):
        return "found", resp[:-6].rsplit(": ", 1)[-1].strip()
    if resp.endswith(": OK") or resp == "OK":
        return "ok", ""
    return "error", resp


def clamd_ping() -> bool:
    try:
        with socket.create_connection((CFG["clamd_host"], int(CFG["clamd_port"])), timeout=2) as s:
            s.sendall(b"zPING\0")
            return _clamd_recv(s) == "PONG"
    except OSError:
        return False


def clamd_scan(path: str) -> tuple[str, str]:
    addr = (CFG["clamd_host"], int(CFG["clamd_port"]))
    try:
        with socket.create_connection(addr, timeout=5) as s:
            s.settimeout(120)
            s.sendall(b"zSCAN " + path.encode("utf-8") + b"\0")
            res = _clamd_parse(_clamd_recv(s))
        if res[0] != "error":
            return res
    except OSError as e:
        res = ("error", str(e))
    try:  # clamd couldn't open the path: stream the bytes instead
        with socket.create_connection(addr, timeout=5) as s, open(path, "rb") as f:
            s.settimeout(120)
            s.sendall(b"zINSTREAM\0")
            for chunk in iter(lambda: f.read(65536), b""):
                s.sendall(struct.pack("!L", len(chunk)) + chunk)
            s.sendall(struct.pack("!L", 0))
            return _clamd_parse(_clamd_recv(s))
    except OSError as e:
        return "error", f"{res[1]} / {e}"


# ---- targets --------------------------------------------------------------- #
def disk(root: str) -> dict:
    try:
        u = shutil.disk_usage(root)
        return {"total": u.total, "free": u.free}
    except OSError:
        return {"total": 0, "free": 0}


def drives() -> list[dict]:
    if os.name != "nt":
        return [{"path": "/", "label": "/", "type": "fixed", **disk("/")}]
    import ctypes
    kinds = {2: "removable", 3: "fixed", 4: "network", 5: "cd"}
    out = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if os.path.exists(root):
            out.append({"path": root, "label": f"{letter}:", "type": kinds.get(ctypes.windll.kernel32.GetDriveTypeW(root), "other"), **disk(root)})
    return out


def user_profiles() -> list[pathlib.Path]:
    root = pathlib.Path(os.path.expandvars(r"%SystemDrive%\Users")) if os.name == "nt" else pathlib.Path("/home")
    skip = {"public", "default", "default user", "all users", "defaultapppool"}
    try:
        return [p for p in root.iterdir() if p.is_dir() and not p.is_symlink() and p.name.lower() not in skip]
    except OSError:
        return []


def quick_targets() -> list[str]:
    t = []
    for u in user_profiles():
        t += [u / "Downloads", u / "Desktop", u / "AppData" / "Local" / "Temp"]
        t += list(u.glob("OneDrive*/Desktop"))
    if os.name == "nt":
        t.append(pathlib.Path(os.path.expandvars(r"%SystemRoot%\Temp")))
    return list(dict.fromkeys(str(p) for p in t if p.exists()))


def expand_targets(targets: list[str]) -> list[str]:
    out = []
    for t in targets:
        if t == "@quick":
            out += quick_targets()
        elif t == "@full":
            out += [d["path"] for d in drives() if d["type"] == "fixed"]
        else:
            out.append(os.path.expandvars(t.strip().strip('"')))
    return list(dict.fromkeys(out))


def set_progress(jid: str, **p):
    with _db_lock, db() as con:
        con.execute("UPDATE jobs SET progress=? WHERE id=?", (json.dumps(p), jid))


def run_scan(jid: str, targets: list[str], action: str = "report", mode: str = "scan") -> dict:
    t0 = time.time()
    cancelled = lambda: jid in JOB_CANCEL
    roots = expand_targets(targets)
    missing = [r for r in roots if not os.path.exists(r)]
    roots = [r for r in roots if os.path.exists(r)]
    if not roots:
        raise RuntimeError("Nothing to scan: " + (", ".join(missing) or "no folders found"))
    check = mode == "check"
    ex = Exclusions(use_rules=not check)
    stats = dict(files=0, scanned=0, excluded=0, too_big=0, unreadable=0, engine_errors=0)
    notes = [f"Not found: {m}" for m in missing]
    if check:
        notes.append("Safety check: your exclusions were ignored, so everything you picked was checked. Nothing was changed.")

    lst = BASE / "data" / f"scan_{jid}.lst"
    set_progress(jid, phase="counting", **stats)
    with lst.open("w", encoding="utf-8") as f:
        for r in roots:
            for p in walk(r, ex, stats, cancelled, CFG.get("max_file_mb", 512)):
                f.write(p + "\n")
                stats["files"] += 1
                if stats["files"] % 2000 == 0:
                    set_progress(jid, phase="counting", **stats)

    clam, yara = clamav_mode(), prepare_yara()
    if not clam:
        notes.append("Antivirus (ClamAV) isn't installed - files were only checked with pattern rules.")
    if not yara:
        notes.append("Pattern rules (YARA) aren't installed - files were only checked by the antivirus.")
    if not clam and not yara:
        raise RuntimeError("No scan engine available. Install ClamAV or YARA.")
    if stats["files"] == 0 and stats["excluded"] and not cancelled():
        notes.insert(0, "Nothing was scanned: everything you picked is in an excluded location or file type. "
                        "Use 'Is this safe?' to check it anyway.")
    if clam == "standalone":
        notes.append("The ClamAV service isn't running, so the antivirus check was slower.")

    findings: dict[str, dict] = {}

    def add(path, engine, rule, info):
        f = findings.setdefault(path, {"path": path, "reasons": [], "level": "suspicious", "quarantined": False})
        f["reasons"].append({"engine": engine, "rule": rule, **info})
        if info["level"] == "dangerous":
            f["level"] = "dangerous"

    def scan_list(file_list: str, with_clam: bool):
        if with_clam:
            try:
                hits, err = clamav_batch(file_list, clam == "daemon")
                stats["engine_errors"] += err
                for path, sig in hits:
                    add(path, "clamav", sig, explain_clamav(sig))
            except Exception as e:
                notes.append(f"Antivirus error: {e}")
        if yara:
            try:
                hits, err = yara_batch(file_list, *yara)
                stats["engine_errors"] += err
                for rule, meta, path in hits:
                    add(path, "yara", rule, explain_yara(rule, meta))
            except Exception as e:
                notes.append(f"Pattern rule error: {e}")

    batch_size = int(CFG.get("scan_batch", 300))
    bfile = BASE / "data" / f"scan_{jid}.batch"
    with lst.open(encoding="utf-8") as f:
        batch = []
        for line in f:
            if cancelled():
                break
            batch.append(line.rstrip("\n"))
            if len(batch) >= batch_size:
                bfile.write_text("\n".join(batch) + "\n", encoding="utf-8")
                scan_list(str(bfile), clam == "daemon")
                stats["scanned"] += len(batch)
                set_progress(jid, phase="scanning", found=len(findings), current=batch[-1], **stats)
                batch = []
        if batch and not cancelled():
            bfile.write_text("\n".join(batch) + "\n", encoding="utf-8")
            scan_list(str(bfile), clam == "daemon")
            stats["scanned"] += len(batch)
    if clam == "standalone" and not cancelled() and stats["files"]:
        set_progress(jid, phase="antivirus", found=len(findings), **stats)
        y, yara = yara, None
        scan_list(str(lst), True)
        yara = y
    for p in (lst, bfile):
        p.unlink(missing_ok=True)

    for path, f in findings.items():
        try:
            f["size"] = os.path.getsize(path)
        except OSError:
            f["size"] = None
        f["sha256"] = sha256(path)
        f["running"] = len(find_processes(path))
        for r in f["reasons"]:
            emit(r["engine"], r["severity"], r["rule"], path, details=r["what"],
                 uniq=f'{r["engine"]}|{r["rule"]}|{path}|{f["sha256"]}', origin="scan")
        if action == "quarantine" and not check:
            try:
                quarantine_file(path)
                f["quarantined"] = True
            except Exception as e:
                notes.append(f"Couldn't quarantine {path}: {e}")

    files = sorted(findings.values(), key=lambda f: (f["level"] != "dangerous", f["path"]))
    verdict = "dangerous" if any(f["level"] == "dangerous" for f in files) else "suspicious" if files else "clean"
    return {"mode": mode, "action": action if not check else "report", "targets": roots, "verdict": verdict,
            "cancelled": cancelled(), "duration": round(time.time() - t0, 1), "stats": stats, "found": len(files),
            "files": files[:500], "truncated": len(files) > 500, "notes": notes,
            "engines": {"clamav": clam, "yara": bool(yara)}}


def quarantine_file(path: str) -> str:
    src = pathlib.Path(path)
    if not src.is_file():
        raise FileNotFoundError(path)
    stop_path(str(src), quiet=True)  # a running program can't be moved
    digest = sha256(str(src))
    dest = pathlib.Path(CFG["quarantine"]) / f"{digest[:16]}_{src.name}.quarantine"
    shutil.move(str(src), dest)
    with _db_lock, db() as con:
        con.execute("INSERT INTO quarantine(original,stored,sha256,time) VALUES(?,?,?,?)",
                    (str(src), str(dest), digest, now()))
    emit("console", "low", "File quarantined", str(src), details=digest)
    return str(dest)


# --------------------------------------------------------------------------- #
# File Intelligence: Authenticode, Mark-of-the-Web (MOTW) and PE Heuristics
# --------------------------------------------------------------------------- #
class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]

_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]

class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


_AUTH_CACHE: dict[tuple, dict] = {}


def is_system_file(path: str) -> bool:
    try:
        p = os.path.normcase(os.path.abspath(path))
        sysroot = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
        return p.startswith(sysroot + os.sep)
    except Exception:
        return False


def verify_authenticode(path: str) -> dict:
    """Verify Windows digital signature using WinVerifyTrust with caching and system catalog awareness."""
    if os.name != "nt" or not path or not os.path.isfile(path):
        return {"signed": False, "valid": False, "status": "unknown", "label": "Not checked", "is_ms": False}
    try:
        st = os.stat(path)
        cache_key = (norm(path), st.st_size, st.st_mtime_ns)
        if cache_key in _AUTH_CACHE:
            return _AUTH_CACHE[cache_key]
    except OSError:
        cache_key = None

    try:
        file_info = _WINTRUST_FILE_INFO(
            cbStruct=ctypes.sizeof(_WINTRUST_FILE_INFO),
            pcwszFilePath=os.path.abspath(path),
            hFile=None,
            pgKnownSubject=None,
        )
        trust_data = _WINTRUST_DATA(
            cbStruct=ctypes.sizeof(_WINTRUST_DATA),
            pPolicyCallbackData=None,
            pSIPClientData=None,
            dwUIChoice=2,               # WTD_UI_NONE
            fdwRevocationChecks=0,      # WTD_REVOKE_NONE
            dwUnionChoice=1,            # WTD_CHOICE_FILE
            pFile=ctypes.pointer(file_info),
            dwStateAction=1,            # WTD_STATEACTION_VERIFY
            hWVTStateData=None,
            pwszURLReference=None,
            dwProvFlags=0x00000040 | 0x00000010, # WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_LIFETIME_SIGNING_FLAG
            dwUIContext=0,
            pSignatureSettings=None,
        )
        ret = ctypes.windll.wintrust.WinVerifyTrust(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(trust_data))
        trust_data.dwStateAction = 2   # WTD_STATEACTION_CLOSE
        ctypes.windll.wintrust.WinVerifyTrust(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(trust_data))
        ret_u = ret & 0xFFFFFFFF

        is_ms = is_system_file(path)
        if ret == 0:
            res = {"signed": True, "valid": True, "status": "trusted", "label": "Verified Digital Signature (Trusted Publisher)", "is_ms": is_ms}
        elif ret_u == 0x800B0100:  # TRUST_E_NOSIGNATURE
            if is_ms:
                res = {"signed": True, "valid": True, "status": "trusted", "label": "Microsoft Windows System Component (Catalog Signed)", "is_ms": True}
            else:
                res = {"signed": False, "valid": False, "status": "unsigned", "label": "Unsigned file (No digital signature)", "is_ms": False}
        elif ret_u == 0x800B0101:  # CERT_E_EXPIRED
            res = {"signed": True, "valid": False, "status": "expired", "label": "Signature Expired", "is_ms": is_ms}
        elif ret_u in (0x80096004, 0x80096010):
            res = {"signed": True, "valid": False, "status": "tampered", "label": "Signature Corrupted / Tampered", "is_ms": is_ms}
        elif ret_u == 0x800B0109:
            res = {"signed": True, "valid": False, "status": "self_signed", "label": "Untrusted Root / Self-Signed", "is_ms": is_ms}
        elif ret_u == 0x800B010C:
            res = {"signed": True, "valid": False, "status": "revoked", "label": "Certificate Revoked", "is_ms": is_ms}
        else:
            res = {"signed": True, "valid": False, "status": "untrusted", "label": f"Invalid or Untrusted Signature ({hex(ret_u)})", "is_ms": is_ms}

        if cache_key:
            if len(_AUTH_CACHE) > 5000:
                _AUTH_CACHE.clear()
            _AUTH_CACHE[cache_key] = res
        return res
    except Exception as e:
        log.debug("Authenticode error on %s: %s", path, e)
        return {"signed": False, "valid": False, "status": "error", "label": "Verification unavailable", "is_ms": False}


def sanitize_url(url: str) -> str:
    """Privacy: strip tokens, passwords, session IDs, and API keys before displaying/storing."""
    if not url:
        return ""
    return re.sub(r"([?&])(token|key|sig|signature|auth|access_token|password|session|code|secret)=[^&#]*",
                  r"\1\2=[REDACTED]", url, flags=re.I)


def read_motw(path: str) -> dict:
    """Read Windows Mark-of-the-Web (Zone.Identifier) stream to find download origin."""
    if os.name != "nt" or not path or not os.path.isfile(path):
        return {"internet": False, "zone": 0, "host_url": "", "referrer_url": "", "label": ""}
    try:
        stream_path = path + ":Zone.Identifier"
        with open(stream_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
        info = {}
        for line in lines:
            if "=" in line:
                k, v = line.split("=", 1)
                info[k.strip().lower()] = v.strip()
        zid = int(info.get("zoneid", 0))
        host_url = sanitize_url(info.get("hosturl", ""))
        ref_url = sanitize_url(info.get("referrerurl", ""))
        is_net = zid >= 3
        label = "Downloaded from the Internet" if is_net else ""
        return {"internet": is_net, "zone": zid, "host_url": host_url, "referrer_url": ref_url, "label": label}
    except Exception:
        return {"internet": False, "zone": 0, "host_url": "", "referrer_url": "", "label": ""}


DECEPTIVE_EXT = re.compile(r'\.(pdf|docx?|xlsx?|pptx?|txt|jpg|png|mp3|mp4|zip|rar)\.(exe|scr|pif|bat|cmd|vbs|vbe|js|jse|hta|cpl|jar|iso)$', re.I)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    occ = [0] * 256
    for b in data:
        occ[b] += 1
    total, ent = len(data), 0.0
    for c in occ:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return round(ent, 2)


def analyze_pe(path: str) -> dict:
    """Static heuristics: entropy, deceptive double extensions, and RLO unicode characters."""
    if not path or not os.path.isfile(path):
        return {"is_pe": False, "entropy": 0.0, "packed": False, "deceptive": False, "rlo": False, "notes": []}
    notes = []
    base = os.path.basename(path)
    # 1. Right-to-Left Override check
    has_rlo = "\u202E" in base
    if has_rlo:
        notes.append("Right-to-Left Override (RLO) character detected in filename (spoofing technique).")
    # 2. Deceptive double extension
    has_deceptive = bool(DECEPTIVE_EXT.search(base))
    if has_deceptive:
        notes.append("Deceptive double extension: executable masquerading as a document.")
    # 3. Entropy & PE header check
    ent = 0.0
    is_pe = False
    try:
        size = os.path.getsize(path)
        if size > 0:
            with open(path, "rb") as f:
                sample = f.read(min(size, 2 * 1024 * 1024))
            is_pe = sample.startswith(b"MZ")
            ent = shannon_entropy(sample)
    except OSError:
        pass
    is_packed = ent >= 7.2
    if is_packed:
        notes.append(f"High entropy ({ent}/8.0): file appears packed or encrypted (common in ransomware and crypters).")
    return {"is_pe": is_pe, "entropy": ent, "packed": is_packed, "deceptive": has_deceptive, "rlo": has_rlo, "notes": notes}


def calculate_risk_score(engine: str, sev: str, program: str, sig: dict, motw: dict, pe: dict) -> dict:
    """Multi-factor risk score engine (0 to 100+)."""
    score = 0
    factors = []

    # Antivirus / YARA signature hit (+100)
    if engine in ("clamav", "yara"):
        score += 100
        factors.append({"points": 100, "reason": f"Malware signature match ({engine.upper()})"})
    elif sev in ("critical", "high"):
        score += 70
        factors.append({"points": 70, "reason": f"High severity behavioral detection ({sev})"})
    elif sev == "medium":
        score += 35
        factors.append({"points": 35, "reason": "Medium severity suspicious activity"})

    p_norm = norm(program) if program else ""
    is_risky_loc = any(x in p_norm for x in ("\\downloads\\", "\\temp\\", "\\appdata\\local\\temp\\"))

    # Unsigned in Downloads/Temp (+25)
    if is_risky_loc and not sig.get("valid"):
        score += 25
        factors.append({"points": 25, "reason": "Unsigned executable running from Downloads or Temp"})

    # Mark-of-the-Web and unsigned (+15)
    if motw.get("internet") and not sig.get("valid"):
        score += 15
        factors.append({"points": 15, "reason": "Downloaded from the Internet with no valid digital signature"})

    # Deceptive double extension or RLO (+30)
    if pe.get("deceptive") or pe.get("rlo"):
        score += 30
        factors.append({"points": 30, "reason": "Deceptive extension or Unicode Right-to-Left Override spoofing"})

    # High Shannon entropy (+10)
    if pe.get("packed"):
        score += 10
        factors.append({"points": 10, "reason": "High Shannon entropy indicating packed or encrypted payload"})

    # Negative factors (trust engine reductions for heuristics)
    if engine not in ("clamav", "yara"):
        if sig.get("valid"):
            if sig.get("is_ms"):
                score -= 50
                factors.append({"points": -50, "reason": "Verified Microsoft-signed Windows system component"})
            else:
                score -= 30
                factors.append({"points": -30, "reason": "Valid trusted Authenticode certificate from verified vendor"})

    final_score = max(0, min(100, score))
    level = "critical" if final_score >= 80 else "high" if final_score >= 60 else "medium" if final_score >= 35 else "low"
    return {"score": final_score, "level": level, "factors": factors}


# --------------------------------------------------------------------------- #
# Programs: stop, block from running, block internet access
# --------------------------------------------------------------------------- #
CRITICAL_NAMES = {"system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
                  "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "explorer.exe", "dwm.exe",
                  "fontdrvhost.exe", "memory compression", "sihost.exe", "taskhostw.exe", "msmpeng.exe",
                  "securityhealthservice.exe", "spoolsv.exe", "conhost.exe", "ctfmon.exe"}


def own_dirs() -> list[str]:
    """Folders of Security Console and the tools it runs (never stopped, blocked or scanned in real time)."""
    out = []
    for d in (str(BASE), str(pathlib.Path(CFG["clamscan"]).parent), str(pathlib.Path(CFG["osqueryi"]).parent)):
        nd = norm(d).rstrip("\\/")
        if len(nd) > 3 and nd not in out:  # never a whole drive
            out.append(nd)
    return out


def protected_reason(path: str) -> str | None:
    """Why a program must not be stopped/blocked, or None if it's allowed."""
    if not path:
        return "No program file was found for this alert."
    n = canonical_path(path)
    name = os.path.basename(n)
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    if name in CRITICAL_NAMES:
        return "This is a core part of Windows. Stopping it would crash or log off the PC."
    if os.name == "nt" and under(n, windir):
        return "This program is part of Windows, so Security Console won't stop or block it."
    for d in own_dirs():
        if under(n, d):
            return "This is one of Security Console's own tools."
    return None


def find_processes(path: str) -> list[dict]:
    if not psutil or not path:
        return []
    n, out = norm(path), []
    for p in psutil.process_iter(["pid", "name", "exe", "create_time", "username"]):
        try:
            exe = p.info.get("exe")
            if exe and norm(exe) == n:
                out.append({"pid": p.info["pid"], "name": p.info["name"], "user": p.info.get("username") or "",
                            "started": dt.datetime.fromtimestamp(p.info["create_time"]).isoformat(timespec="seconds")})
        except (psutil.Error, OSError, ValueError):
            continue
    return out


def _kill_tree(proc) -> int:
    n = 0
    try:
        kids = proc.children(recursive=True)
    except psutil.Error:
        kids = []
    for p in kids + [proc]:
        try:
            p.kill()
            n += 1
        except psutil.Error:
            pass
    return n


def stop_pid(pid: int) -> dict:
    if not psutil:
        raise RuntimeError("Process control isn't available")
    if pid in (0, 4, os.getpid()):
        raise RuntimeError("This process can't be stopped.")
    try:
        p = psutil.Process(pid)
        exe = p.exe()
    except psutil.NoSuchProcess:
        return {"stopped": 0}
    except psutil.AccessDenied:
        raise RuntimeError("Windows didn't allow stopping this process.")
    why = protected_reason(exe)
    if why:
        raise RuntimeError(why)
    return {"stopped": _kill_tree(p), "path": exe}


def stop_path(path: str, quiet: bool = False) -> dict:
    why = protected_reason(path)
    if why:
        if quiet:
            return {"stopped": 0}
        raise RuntimeError(why)
    stopped = 0
    for info in find_processes(path):
        try:
            stopped += _kill_tree(psutil.Process(info["pid"]))
        except psutil.Error:
            pass
    return {"stopped": stopped}


def fw_rule_name(path: str) -> str:
    return f"Security Console block {hashlib.sha1(norm(path).encode()).hexdigest()[:8]} {os.path.basename(path)}"[:240]


def firewall_block(path: str, block: bool):
    if os.name != "nt":
        raise RuntimeError("The Windows Firewall isn't available on this system")
    name = fw_rule_name(path)
    run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], timeout=30)
    if block:
        for direction in ("out", "in"):
            r = run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={direction}",
                     "action=block", f"program={path}", "enable=yes"], timeout=30)
            if r.returncode != 0:
                raise RuntimeError("Windows Firewall refused the rule: " + (r.stdout or r.stderr).strip()[:200])


_BLOCK = {"rows": None, "hashes": {}}


def blocked_rows() -> list[dict]:
    if _BLOCK["rows"] is None:
        with db() as con:
            _BLOCK["rows"] = [dict(r) for r in con.execute("SELECT * FROM blocked ORDER BY id DESC")]
    return _BLOCK["rows"]


def blocked_match(exe: str) -> dict | None:
    if not exe or protected_reason(exe):  # never touch Windows' own programs or our tools
        return None
    n = norm(exe)
    rows = [r for r in blocked_rows() if r["run_block"]]
    for r in rows:
        if norm(r["path"]) == n:
            return r
    hashes = {r["sha256"]: r for r in rows if r["sha256"]}
    if not hashes:
        return None
    try:  # same file renamed or copied elsewhere
        st = os.stat(exe)
        key = (n, st.st_size, st.st_mtime_ns)
    except OSError:
        return None
    if key not in _BLOCK["hashes"]:
        if len(_BLOCK["hashes"]) > 5000:
            _BLOCK["hashes"].clear()
        _BLOCK["hashes"][key] = sha256(exe)
    return hashes.get(_BLOCK["hashes"][key])


def enforce_block(pid: int, exe: str, row: dict) -> bool:
    try:
        n = _kill_tree(psutil.Process(pid)) if psutil else 0
    except psutil.Error:
        n = 0
    if n:
        emit("console", "medium", "Blocked program was stopped", exe,
             details=f"'{os.path.basename(exe)}' tried to start and was stopped because you blocked it.",
             uniq=f"blockstop|{pid}|{exe}|{int(time.time() // 60)}", origin="realtime")
    return bool(n)


def block_enforcer():
    """Every 2 seconds: stop any running program that's on the blocked list."""
    seen: set = set()
    while True:
        time.sleep(2)
        if not psutil or not any(r["run_block"] for r in blocked_rows()) or is_paused():
            continue
        try:
            cur = set()
            for p in psutil.process_iter(["pid", "exe", "create_time"]):
                key = (p.info["pid"], p.info.get("create_time"))
                cur.add(key)
                if key in seen:
                    continue
                exe = p.info.get("exe")
                row = blocked_match(exe) if exe else None
                if row:
                    enforce_block(p.info["pid"], exe, row)
            seen = cur
        except Exception:
            log.exception("block enforcer")


# --------------------------------------------------------------------------- #
# Plain-English explanations for every alert
# --------------------------------------------------------------------------- #
SEV_TEXT = {
    "critical": ("Serious - act now", "This matches something that's almost always harmful."),
    "high": ("High - deal with it today", "This is often a sign of malware or an attack."),
    "medium": ("Worth checking - often harmless", "Normal programs sometimes do this too, so check what caused it."),
    "low": ("Low - usually just information", "This is unlikely to be harmful on its own."),
}
PATH_RE = re.compile(r'([A-Za-z]:\\[^|"<>\n\r*?]+?\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|msi|scr|com|cpl))',
                     re.IGNORECASE)

SIGMA_TOPICS = [
    (("lsass", "mimikatz", "credential", "password", "sam database", "dump", "secretsdump", "kerberos", "ntds"), dict(
        title="Something tried to read saved passwords",
        what="A program tried to access the part of Windows that stores sign-in secrets. Password-stealing malware does this.",
        steps=["Stop the program and block it.", "Run a Full scan.",
               "From a different, trusted device, change the passwords for your email, bank and Microsoft account.",
               "If this is a work PC, tell your IT team straight away."],
        fp="Rarely a false alarm. Some backup and security tools do this; only mute it if you're sure.")),
    (("defender", "antivirus", "tamper", "disable security", "exclusion", "amsi"), dict(
        title="Something tried to weaken your security",
        what="A program tried to turn off or bypass Microsoft Defender or other protection. Malware does this so it isn't caught.",
        steps=["Open Windows Security and make sure Real-time protection is On.", "Stop and block the program that did it.",
               "Run a Full scan."],
        fp="Usually not a false alarm, unless you changed Defender settings yourself just now.")),
    (("ransom", "shadow cop", "vssadmin", "wbadmin", "bcdedit", "backup"), dict(
        title="Backups or recovery settings were changed",
        what="Something deleted shadow copies or changed recovery settings. Ransomware does this before locking files.",
        steps=["Disconnect from the internet if files start getting renamed or won't open.", "Stop and block the program.",
               "Run a Full scan.", "Make sure you have a backup on an external drive or in the cloud."],
        fp="Rarely a false alarm, unless you were managing backups yourself.")),
    (("clear", "wevtutil", "log deleted", "audit policy", "eventlog"), dict(
        title="Windows logs were cleared or changed",
        what="Event logs record what happens on the PC. Attackers clear them to hide their tracks.",
        steps=["If you didn't clear logs yourself, run a Full scan.", "Review the other alerts from around the same time."],
        fp="Can happen if you used a PC 'cleaner' tool.")),
    (("powershell", "pwsh", "encoded", "-enc", "iex", "invoke-expression", "downloadstring", "scriptblock"), dict(
        title="A PowerShell command ran in a way attackers often use",
        what="PowerShell is a built-in Windows tool that runs commands and scripts. This one hid its command, downloaded "
             "something, or used tricks that malware often uses.",
        steps=["Look at 'Program' and 'Technical details' below to see what ran it.",
               "If it's software you installed and trust (for example a printer, RGB lighting or driver utility in "
               "Program Files), click 'Not a threat' to stop these alerts for that program.",
               "If you don't recognise it, or it came from Downloads, Temp or AppData: stop it, block it and run a Quick scan."],
        fp="Common false alarm: hardware utilities (RGB lighting, MSI/ASUS/Razer tools), updaters and IT management software.")),
    (("wmi", "wsman", "winrm", "remote management", "com object", "dcom", "comhijack", "com hijack"), dict(
        title="Windows management features were used",
        what="WMI, WinRM (WSMan) and COM let programs control Windows. Admin tools and hardware utilities use them, "
             "but attackers use them to run hidden commands or stay on the PC.",
        steps=["Check which program caused it (see 'Program' below).",
               "If it's a tool you trust, such as lighting, monitoring or driver software, click 'Not a threat'.",
               "If you don't recognise it, stop and block it, then run a Quick scan."],
        fp="Very common false alarm with RGB lighting software (e.g. MSI Mystic Light), monitoring tools and Dell/HP/Lenovo utilities.")),
    (("scheduled task", "schtasks", "task scheduler", "at.exe"), dict(
        title="A program set itself to run on a schedule",
        what="Scheduled tasks start programs automatically at certain times. Updaters use them, and so does malware that wants to come back.",
        steps=["If you just installed or updated software, this is probably normal - mark it Resolved.",
               "Otherwise open Check my PC > Scheduled tasks and look for a name you don't recognise.",
               "Stop and block any program you don't recognise, then run a Quick scan."],
        fp="Often normal: Google, Microsoft, Adobe and driver updaters create tasks.")),
    (("service", "sc.exe", "new service"), dict(
        title="A new background service was installed",
        what="Services are programs that run in the background, even when nobody is signed in.",
        steps=["If you just installed software or a driver, this is probably normal.",
               "Otherwise check Check my PC > Installed services for a name you don't recognise.",
               "Stop and block it if it's unknown, then run a Full scan."],
        fp="Often normal after installing drivers, games, VPNs or antivirus software.")),
    (("run key", "autorun", "startup", "registry", "reg.exe", "winlogon", "userinit"), dict(
        title="Something set itself to start with Windows",
        what="A program added itself to the list of things that start automatically.",
        steps=["If you just installed it, this is normal.",
               "Otherwise open Task Manager > Startup apps and disable anything you don't recognise.",
               "Stop and block unknown programs, then run a Quick scan."],
        fp="Often normal for chat apps, cloud storage and hardware utilities.")),
    (("user", "account", "admin", "group", "net.exe", "net1"), dict(
        title="An account was created or given more power",
        what="A Windows account was added, or given administrator rights. Attackers do this to keep access.",
        steps=["Open Settings > Accounts > Other users. Check every account is someone you know.",
               "Remove administrator rights from anyone who doesn't need them.",
               "If an unknown account appeared, change your password and run a Full scan."],
        fp="Normal if you or your IT team just added a user.")),
    (("logon", "login", "brute", "failed", "rdp", "remote desktop", "authentication"), dict(
        title="Unusual sign-in activity",
        what="There were failed or unusual sign-in attempts. Repeated failures can mean someone is guessing passwords.",
        steps=["If it wasn't you, change your Windows password.",
               "If you don't use Remote Desktop, turn it off in Settings > System > Remote Desktop."],
        fp="Normal if you mistyped your password a few times.")),
    (("certutil", "bitsadmin", "download", "curl", "wget", "invoke-webrequest"), dict(
        title="A Windows tool was used to download a file",
        what="Built-in tools were used to fetch something from the internet. Malware uses them to download more malware.",
        steps=["Check which program did it (see 'Program' below).",
               "Run 'Is this safe?' on your Downloads and Temp folders.", "Stop and block anything you don't recognise."],
        fp="Sometimes normal for installers and IT scripts.")),
    (("rundll32", "regsvr32", "mshta", "wscript", "cscript", "msiexec", "installutil", "lolbin", "lolbas"), dict(
        title="A Windows helper was used to run code",
        what="Windows includes small helper programs that can run other code. Attackers use them because they're trusted.",
        steps=["Check which program started it (see 'Technical details').",
               "If it happened while you were installing something you trust, mark it Resolved.",
               "Otherwise run a Quick scan and block anything unknown."],
        fp="Sometimes normal during software installs and updates.")),
    (("office", "winword", "excel", "outlook", "macro", "powerpnt"), dict(
        title="An Office document started another program",
        what="A Word, Excel or Outlook file launched another program. Harmful documents and email attachments do this.",
        steps=["Close the document and don't enable macros or editing.", "Run 'Is this safe?' on the file.",
               "Delete the email or file if you weren't expecting it."],
        fp="Rarely normal, unless you use business add-ins.")),
    (("uac", "bypass", "elevat", "privilege", "token"), dict(
        title="Something tried to get administrator rights",
        what="A program tried to give itself more power without asking you.",
        steps=["Stop and block the program.", "Run a Full scan."],
        fp="Rarely a false alarm.")),
    (("network", "connection", "dns", "proxy", "tunnel", "tor"), dict(
        title="Unusual network activity",
        what="A program made a network connection that matches attacker behavior.",
        steps=["Check which program did it.", "If you don't recognise it, block its internet access and run a Quick scan."],
        fp="Can be normal for VPNs, games and remote-support tools.")),
]
SIGMA_DEFAULT = dict(
    title="Activity that matches a known attack pattern",
    what="Windows recorded something that looks like techniques attackers use. On its own it doesn't prove anything is wrong.",
    steps=["Look at the program and technical details below.",
           "If it's software you trust, click 'Not a threat'.", "If you're unsure, run a Quick scan."],
    fp="Medium and low alerts are often caused by normal software.")

HUNT_TOPICS = {
    "Startup programs": ("A new program now starts with Windows",
                         "Something was added to the list of programs that start when you sign in.",
                         ["If you just installed software, this is normal - mark it Resolved.",
                          "If you don't recognise it, open Task Manager > Startup apps and disable it."]),
    "Installed services": ("A new background service appeared",
                           "A new program now runs in the background, even when nobody is signed in.",
                           ["Normal after installing drivers or apps.", "If you don't recognise it, block it and run a Full scan."]),
    "Scheduled tasks": ("A new scheduled task appeared",
                        "A program will now run automatically at certain times.",
                        ["Normal for updaters.", "If you don't recognise the name, block the program it runs and run a Quick scan."]),
    "Local administrators": ("Someone new has full control of this PC",
                             "An account was added to the Administrators group.",
                             ["Open Settings > Accounts > Other users and check you know this account.",
                              "If you don't, remove its administrator rights and change your password."]),
    "Listening ports": ("A program is accepting connections from the network",
                        "A program opened a door for other computers to connect to it.",
                        ["Normal for games, chat, sharing and remote-support tools.",
                         "If you don't recognise the program, block its internet access."]),
    "Installed software": ("New software was installed",
                           "A new program appeared in the list of installed software.",
                           ["If you installed it, mark it Resolved.",
                            "If you didn't, uninstall it from Settings > Apps > Installed apps and run a Quick scan."]),
}


def event_program(e: dict) -> str:
    if e["engine"] in ("clamav", "yara"):
        return e["target"]
    if e["engine"] == "console" and PATH_RE.match(e.get("target") or ""):
        return e["target"]
    text = f'{e.get("target", "")} {e.get("details", "")}'
    if e["engine"] == "osquery":
        try:
            d = json.loads(e.get("details") or "{}")
            for k in ("path", "action"):
                m = PATH_RE.search(str(d.get(k, "")))
                if m:
                    return m.group(1)
        except ValueError:
            pass
    m = PATH_RE.search(text)
    return m.group(1).strip() if m else ""


def explain_event(e: dict) -> dict:
    eng, sev, rule = e["engine"], e["severity"], e["rule"]
    level_title, level_text = SEV_TEXT.get(sev, SEV_TEXT["medium"])
    program = event_program(e)
    out = {"severity": sev, "level_title": level_title, "level_text": level_text, "program": program,
           "program_name": re.split(r"[\\/]", program)[-1] if program else "", "rule": rule}
    if eng == "clamav":
        info = explain_clamav(rule)
        name = rule.split(".")[0].lower()
        if "test" in rule.lower():
            out.update(title="Antivirus test file", what=info["what"],
                       steps=["Nothing to worry about. Delete the file or mark this Resolved."],
                       fp="This is a harmless test file, not real malware.")
        elif name == "pua":
            out.update(title="Potentially unwanted program", what=info["what"] + " Examples: toolbars, 'PC optimizers', bundled installers.",
                       steps=["If you didn't mean to install it, uninstall it from Settings > Apps > Installed apps.",
                              "Or quarantine the file.", "If you trust it, click 'Not a threat'."],
                       fp="Sometimes flags real tools you chose to install, such as remote-access or download managers.")
        elif "encrypted" in rule.lower():
            out.update(title="Password-protected archive", what=info["what"],
                       steps=["Only open it if you trust who sent it.", "Ask the sender for an unprotected copy so it can be checked."],
                       fp="Often harmless - but attackers use passwords to hide malware from antivirus.")
        else:
            out.update(title="Known malware found" if info["level"] == "dangerous" else "Suspicious file found",
                       what=info["what"],
                       steps=["Don't open or run this file.", "Quarantine it (button below). Nothing is deleted.",
                              "If it's running, stop it and block it.", "Run a Quick scan to look for related files.",
                              "If you already opened it, change your important passwords from another device."],
                       fp="Antivirus matches on known samples are rarely wrong.")
    elif eng == "yara":
        test = "test" in rule.lower()
        what = (e.get("details") or "").split(" [Real-time:")[0] or f'The file matches the pattern rule "{rule}".'
        out.update(title="Pattern rule test" if test else "File matches a known-bad pattern",
                   what=what if test else f"{what.rstrip('.')}. Pattern rules look for tell-tale code or text that malware contains.",
                   steps=["Nothing to worry about - this is the built-in test rule."] if test else
                   ["Don't open the file.", "Quarantine it (button below).", "If it's running, stop it and block it.",
                    "Run a Quick scan."],
                   fp="Harmless test." if test else "Possible if the file is a security tool or contains example malware text.")
    elif eng == "sigma":
        title = rule.lower()
        rest = f'{e.get("target") or ""} {e.get("details") or ""}'.lower()
        topic = (next((t for keys, t in SIGMA_TOPICS if any(k in title for k in keys)), None)        # rule name first
                 or next((t for keys, t in SIGMA_TOPICS if any(k in rest for k in keys)), SIGMA_DEFAULT))
        out.update(title=topic["title"], what=topic["what"], steps=topic["steps"], fp=topic["fp"])
    elif eng == "osquery":
        key = rule.replace("New: ", "")
        t = HUNT_TOPICS.get(key, ("A change to your PC", "Security Console noticed a change since the last check.",
                                  ["If you made this change, mark it Resolved."]))
        out.update(title=t[0], what=t[1], steps=t[2], fp="Usually caused by software you installed or updated.")
    else:
        out.update(title=rule, what=e.get("details") or "A note from Security Console.",
                   steps=["No action needed."], fp="")
    why = protected_reason(program) if program else "No program file was found for this alert."
    file_exists = bool(program) and os.path.isfile(program)
    out["running"] = find_processes(program) if program else []
    row = next((r for r in blocked_rows() if program and norm(r["path"]) == norm(program)), None)
    out["blocked"] = {"id": row["id"], "run": bool(row["run_block"]), "firewall": bool(row["firewall"])} if row else None
    out["can"] = {
        "quarantine": eng in ("clamav", "yara") and file_exists and not why,
        "stop": bool(out["running"]) and not why,
        "block": bool(program) and not why and file_exists,
        "firewall": bool(program) and not why and file_exists,
        "mute": eng not in ("console",),
    }
    out["protected_reason"] = why if program else ""
    out["mute_match"] = program
    out["mitre_attack"] = e.get("mitre_attack") or map_mitre(eng, rule, f"{e.get('target')} {e.get('details')}")
    out["signature"] = verify_authenticode(program) if file_exists else {"signed": False, "valid": False, "status": "none", "label": "", "is_ms": False}
    out["motw"] = read_motw(program) if file_exists else {"internet": False, "zone": 0, "host_url": "", "referrer_url": "", "label": ""}
    out["pe"] = analyze_pe(program) if file_exists else {"entropy": 0.0, "packed": False, "deceptive": False, "rlo": False, "notes": []}
    out["risk_score"] = calculate_risk_score(eng, sev, program, out["signature"], out["motw"], out["pe"])
    return out


# --------------------------------------------------------------------------- #
# Threat hunts (osquery)
# --------------------------------------------------------------------------- #
HUNTS = {
    "startup_items": {"title": "Startup programs", "sql": "SELECT name, path, source, username FROM startup_items;",
                      "severity": "medium", "key": ["name", "path"], "mitre": "T1547.001 - Registry Run Keys / Startup Folder"},
    "services": {"title": "Installed services",
                 "sql": "SELECT name, display_name, path, start_type, user_account FROM services;",
                 "severity": "medium", "key": ["name", "path"], "mitre": "T1543.003 - Windows Service"},
    "scheduled_tasks": {"title": "Scheduled tasks", "sql": "SELECT name, path, action, enabled FROM scheduled_tasks WHERE enabled=1;",
                        "severity": "medium", "key": ["name", "action"], "mitre": "T1053.005 - Scheduled Task"},
    "listening_ports": {"title": "Listening ports",
                        "sql": "SELECT DISTINCT p.name, p.path, l.port, l.protocol, l.address FROM listening_ports l "
                               "JOIN processes p USING(pid) WHERE l.port <> 0;",
                        "severity": "low", "key": ["name", "port", "protocol"], "mitre": "T1049 - System Network Connections Discovery"},
    "local_admins": {"title": "Local administrators",
                     "sql": "SELECT u.username, u.uid FROM users u JOIN user_groups ug ON u.uid=ug.uid "
                            "JOIN groups g ON g.gid=ug.gid WHERE g.groupname='Administrators';",
                     "severity": "high", "key": ["username"], "mitre": "T1098 - Account Manipulation"},
    "etc_hosts": {"title": "Hosts file entries", "sql": "SELECT hostnames, address FROM etc_hosts;",
                  "severity": "high", "key": ["hostnames", "address"], "mitre": "T1565.001 - Stored Data Manipulation"},
    "processes": {"title": "Running programs", "sql": "SELECT pid, name, path, cmdline FROM processes WHERE path <> '';",
                  "severity": None, "key": None},
    "unsigned_running": {"title": "Unsigned running programs",
                         "sql": "SELECT p.pid, p.name, p.path FROM processes p JOIN authenticode a ON a.path=p.path "
                                "WHERE a.result <> 'trusted';", "severity": None, "key": None},
    "installed_programs": {"title": "Installed software", "sql": "SELECT name, version, publisher, install_date FROM programs;",
                           "severity": "low", "key": ["name", "version"]},
}


def list_programs() -> list[dict]:
    rows = []
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "memory_info", "create_time", "ppid"]):
        i = p.info
        if i["pid"] in (0, 4):
            continue
        try:
            started = dt.datetime.fromtimestamp(i["create_time"]).isoformat(timespec="seconds") if i.get("create_time") else ""
        except (OSError, ValueError):
            started = ""
        rows.append({"pid": i["pid"], "name": i.get("name") or "?", "path": i.get("exe") or "",
                     "cmdline": " ".join(i.get("cmdline") or [])[:1500], "user": i.get("username") or "",
                     "memory": i["memory_info"].rss if i.get("memory_info") else 0, "started": started,
                     "parent_pid": i.get("ppid")})
    return rows


def run_hunt(name: str, record: bool = True) -> dict:
    h = HUNTS[name]
    if name == "processes" and psutil:
        return {"hunt": name, "title": h["title"], "rows": list_programs(), "new": 0}
    rows = osquery(h["sql"])
    if name == "startup_items" and not record:
        for r in rows:
            r["enabled"] = startup_enabled(r.get("name", ""), r.get("source", ""), r.get("path", ""))
    new_rows = []
    if record and h["key"]:
        with _db_lock, db() as con:
            first = con.execute("SELECT COUNT(*) FROM baseline WHERE hunt=?", (name,)).fetchone()[0] == 0
            for r in rows:
                if is_self_row(r):
                    continue  # Security Console's own tasks, services and ports
                k = "|".join(str(r.get(x, "")) for x in h["key"])
                rh = hashlib.sha1(k.encode()).hexdigest()
                if con.execute("INSERT OR IGNORE INTO baseline VALUES(?,?,?)", (name, rh, now())).rowcount and not first:
                    new_rows.append((r, k, rh))
        for r, k, rh in new_rows:
            mitre_tag = h.get("mitre", "T1547 - Boot or Logon Autostart Execution")
            emit("osquery", h["severity"], f"Persistence Change: New {h['title']}", k, details=json.dumps(r),
                 uniq=f"osq|{name}|{rh}", origin="schedule", mitre=mitre_tag)
    return {"hunt": name, "title": h["title"], "rows": rows, "new": len(new_rows)}


# --------------------------------------------------------------------------- #
# Jobs, maintenance and scheduler
# --------------------------------------------------------------------------- #
def start_job(kind: str, target: str, fn, pass_id: bool = False) -> str:
    jid = uuid.uuid4().hex[:12]
    with _db_lock, db() as con:
        con.execute("INSERT INTO jobs(id,kind,target,state,started) VALUES(?,?,?,?,?)", (jid, kind, target, "running", now()))

    def worker():
        try:
            res, state = (fn(jid) if pass_id else fn()), "done"
            if isinstance(res, dict) and res.get("cancelled"):
                state = "cancelled"
        except Exception as e:
            log.exception("job %s failed", kind)
            res, state = {"error": str(e)}, "error"
        finally:
            JOB_CANCEL.discard(jid)
        with _db_lock, db() as con:
            con.execute("UPDATE jobs SET state=?, finished=?, result=? WHERE id=?",
                        (state, now(), json.dumps(res, default=str), jid))

    threading.Thread(target=worker, daemon=True).start()
    return jid


def start_scan(targets: list[str], action: str, mode: str, label: str) -> str:
    return start_job("scan", label, lambda jid: run_scan(jid, targets, action, mode), pass_id=True)


def update_signatures() -> dict:
    clamdir = pathlib.Path(CFG["clamscan"]).parent
    fresh = clamdir / "freshclam.exe"
    if not fresh.exists():
        raise RuntimeError("ClamAV isn't installed")
    svc = CFG["services"].get("freshclam", "FreshClam")
    was = svc_state(svc) == "running"
    if was:
        run(["sc", "stop", svc], timeout=60)
        time.sleep(3)
    try:
        r = run([str(fresh), f"--config-file={clamdir / 'freshclam.conf'}"], timeout=1800, cwd=str(clamdir))
    finally:
        if was:
            run(["sc", "start", svc], timeout=60)
    text = (r.stdout + r.stderr).strip()
    updated = [l.strip() for l in text.splitlines() if "updated" in l.lower() or "up-to-date" in l.lower() or "up to date" in l.lower()]
    if r.returncode not in (0, 1):
        raise RuntimeError(text[-400:] or "freshclam failed")
    return {"summary": "; ".join(updated[-4:]) or "Virus definitions checked.", "output": text[-1500:]}


def update_rules() -> dict:
    exe = pathlib.Path(CFG["hayabusa"])
    if not exe.exists():
        raise RuntimeError("Hayabusa isn't installed")
    with _HB_LOCK:
        r = run([str(exe), "update-rules", "-q"], timeout=900, cwd=str(exe.parent))
    text = (r.stdout + r.stderr).strip()
    if r.returncode != 0:
        raise RuntimeError(text[-400:] or "Rule update failed")
    return {"summary": "Behavior rules are up to date.", "output": text[-1500:]}


def cleanup_history(days: int | None = None) -> dict:
    days = CFG.get("history_days", 90) if days is None else days
    if not days:
        return {"events": 0, "jobs": 0}
    cutoff = (dt.datetime.now() - dt.timedelta(days=int(days))).isoformat(timespec="seconds")
    with _db_lock, db() as con:
        ev = con.execute("DELETE FROM events WHERE time<? AND status!='new'", (cutoff,)).rowcount
        jb = con.execute("DELETE FROM jobs WHERE started<? AND state!='running'", (cutoff,)).rowcount
    return {"events": ev, "jobs": jb, "summary": f"Removed {ev} old alerts and {jb} old activity entries."}


def self_test(jid: str) -> dict:
    d = BASE / "data" / "selftest"
    d.mkdir(parents=True, exist_ok=True)
    test_yara = d / "security-console-test.txt"
    test_eicar = d / "eicar-standard-test.txt"
    eicar_blocked_on_write = False
    try:
        # 1. YARA test marker
        test_yara.write_text("SECURITY_CONSOLE_YARA_TEST\n", encoding="utf-8")
        # 2. Harmless EICAR standard test string
        eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        try:
            test_eicar.write_text(eicar, encoding="ascii")
        except (PermissionError, OSError):
            # If Windows Defender or ClamAV immediately intercepts and quarantines the file, detection works!
            eicar_blocked_on_write = True

        res = run_scan(jid, [str(d)], "report", "check")
        yara_ok = any("SC_Test_Marker" == r["rule"] for f in res["files"] for r in f["reasons"])
        clam_ok = eicar_blocked_on_write or any("eicar" in str(r.get("rule", "")).lower() for f in res["files"] for r in f["reasons"]) or (not test_eicar.exists())
        ok = yara_ok or clam_ok

        # Immediately resolve self-test alerts so the Threats list is not contaminated
        with _db_lock, db() as con:
            con.execute("UPDATE events SET status='resolved', note='[Self-Test Verification]' WHERE target LIKE ?", (str(d) + "%",))
        res["self_test"] = {"ok": ok, "yara_ok": yara_ok, "clamav_ok": clam_ok, "clamd": clamd_ping(), "engines": res["engines"]}
        return res
    finally:
        shutil.rmtree(d, ignore_errors=True)


def daily_due() -> bool:
    if not CFG.get("daily_scan_enabled", True):
        return False
    try:
        hh, mm = [int(x) for x in str(CFG.get("daily_scan_time", "12:30")).split(":")]
    except ValueError:
        hh, mm = 12, 30
    n = dt.datetime.now()
    return get_setting("last_daily") != n.date().isoformat() and (n.hour, n.minute) >= (hh, mm)


def scheduler():
    last = {"sigma": 0, "hunts": 0, "cleanup": 0}
    while True:
        t = time.time()
        if is_paused():
            time.sleep(15)
            continue
        try:
            se = int(CFG.get("sigma_every", 15) or 0)
            if se and t - last["sigma"] >= se * 60:
                last["sigma"] = t
                start_job("sigma", "Windows event logs", lambda: {"new_events": run_sigma()})
            he = int(CFG.get("hunts_every", 60) or 0)
            if he and t - last["hunts"] >= he * 60:
                last["hunts"] = t
                start_job("hunts", "System change check",
                          lambda: {n: run_hunt(n)["new"] for n, h in HUNTS.items() if h["key"]})
            if daily_due():
                set_setting("last_daily", dt.date.today().isoformat())
                scope = "@full" if CFG.get("daily_scan_scope") == "full" else "@quick"
                start_scan([scope], CFG.get("daily_scan_action", "report"), "scan", "Daily automatic scan")
            if t - last["cleanup"] >= 6 * 3600:
                last["cleanup"] = t
                cleanup_history()
        except Exception:
            log.exception("scheduler")
        time.sleep(30)


# --------------------------------------------------------------------------- #
# REAL-TIME PROTECTION (report only, optional auto-stop)
# --------------------------------------------------------------------------- #
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
EVT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
RISKY_EXT = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx", ".msi", ".msp", ".msix", ".appx",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".url",
    ".jar", ".py", ".reg", ".inf", ".chm", ".iso", ".img", ".vhd", ".vhdx", ".zip", ".rar", ".7z", ".cab", ".gz", ".tar",
    ".doc", ".docm", ".docx", ".dot", ".dotm", ".xls", ".xlsm", ".xlsx", ".xlsb", ".xlam",
    ".ppt", ".pptm", ".pptx", ".rtf", ".pdf", ".one", ".html", ".htm", ".svg",
}
PARTIAL_EXT = {".crdownload", ".part", ".partial", ".download", ".tmp", ".temp", ".opdownload", ".!ut", ".!qb"}


def parse_event_xml(xml: str) -> dict | None:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    sysn = root.find(f"{EVT_NS}System")
    if sysn is None:
        return None
    ev = {"EventID": int((sysn.findtext(f"{EVT_NS}EventID") or "0").strip() or 0),
          "RecordID": int((sysn.findtext(f"{EVT_NS}EventRecordID") or "0").strip() or 0)}
    data = root.find(f"{EVT_NS}EventData")
    if data is not None:
        for d in data.findall(f"{EVT_NS}Data"):
            ev[d.get("Name", "")] = (d.text or "").strip()
    return ev


class SysmonReader:
    def __init__(self):
        self.last = None
        self.method = "pywin32" if win32evtlog else ("wevtutil" if os.name == "nt" else None)

    def _query(self, xpath: str, newest_first: bool = False, limit: int = 500) -> list[str]:
        if self.method == "pywin32":
            flags = win32evtlog.EvtQueryChannelPath | (
                win32evtlog.EvtQueryReverseDirection if newest_first else win32evtlog.EvtQueryForwardDirection)
            h = win32evtlog.EvtQuery(SYSMON_CHANNEL, flags, xpath)
            out = []
            while len(out) < limit:
                try:
                    batch = win32evtlog.EvtNext(h, min(100, limit - len(out)))
                except Exception:
                    break
                if not batch:
                    break
                out += [win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml) for e in batch]
            return out
        if self.method == "wevtutil":
            args = ["wevtutil", "qe", SYSMON_CHANNEL, f"/q:{xpath}", "/f:xml", "/e:Events", f"/c:{limit}"]
            if newest_first:
                args.append("/rd:true")
            r = run(args, timeout=30)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.strip() or "wevtutil failed")
            return [ET.tostring(e, encoding="unicode") for e in ET.fromstring(r.stdout or "<Events/>")]
        raise RuntimeError("Windows event log isn't available on this system")

    def open(self):
        xs = self._query("*", newest_first=True, limit=1)
        ev = parse_event_xml(xs[0]) if xs else None
        self.last = ev["RecordID"] if ev else 0

    def poll(self) -> list[dict]:
        if self.last is None:
            self.open()
            return []
        xs = self._query(f"*[System[(EventID=1 or EventID=11) and EventRecordID>{self.last}]]")
        evs = [e for e in (parse_event_xml(x) for x in xs) if e]
        if evs:
            self.last = max(self.last, max(e["RecordID"] for e in evs))
        return evs


DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"


class DefenderReader:
    def __init__(self):
        self.last = None
        self.method = "pywin32" if win32evtlog else ("wevtutil" if os.name == "nt" else None)

    def _query(self, xpath: str, newest_first: bool = False, limit: int = 100) -> list[str]:
        if self.method == "pywin32":
            flags = win32evtlog.EvtQueryChannelPath | (
                win32evtlog.EvtQueryReverseDirection if newest_first else win32evtlog.EvtQueryForwardDirection)
            try:
                h = win32evtlog.EvtQuery(DEFENDER_CHANNEL, flags, xpath)
                out = []
                while len(out) < limit:
                    try:
                        batch = win32evtlog.EvtNext(h, min(50, limit - len(out)))
                    except Exception:
                        break
                    if not batch:
                        break
                    out += [win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml) for e in batch]
                return out
            except Exception:
                return []
        if self.method == "wevtutil":
            args = ["wevtutil", "qe", DEFENDER_CHANNEL, f"/q:{xpath}", "/f:xml", "/e:Events", f"/c:{limit}"]
            if newest_first:
                args.append("/rd:true")
            r = run(args, timeout=20)
            if r.returncode != 0:
                return []
            try:
                return [ET.tostring(e, encoding="unicode") for e in ET.fromstring(r.stdout or "<Events/>")]
            except Exception:
                return []
        return []

    def open(self):
        xs = self._query("*", newest_first=True, limit=1)
        ev = parse_event_xml(xs[0]) if xs else None
        self.last = ev["RecordID"] if ev else 0

    def poll(self) -> list[dict]:
        if self.last is None:
            self.open()
            return []
        xs = self._query(f"*[System[(EventID=1116 or EventID=1117 or EventID=1121 or EventID=1122) and EventRecordID>{self.last}]]")
        evs = [e for e in (parse_event_xml(x) for x in xs) if e]
        if evs:
            self.last = max(self.last, max(e["RecordID"] for e in evs))
        return evs


def export_recent_events(channel: str, target: pathlib.Path, ms: int) -> bool:
    query = f"*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    target.unlink(missing_ok=True)
    if win32evtlog is not None:
        try:
            win32evtlog.EvtExportLog(channel, str(target), win32evtlog.EvtExportLogChannelPath, query)
            return target.exists()
        except Exception:
            target.unlink(missing_ok=True)
    if os.name != "nt":
        return False
    r = run(["wevtutil", "epl", channel, str(target), f"/q:{query}", "/ow:true"], timeout=60)
    return r.returncode == 0 and target.exists()


class _WatchHandler(FileSystemEventHandler):
    def __init__(self, rt):
        super().__init__()
        self.rt = rt

    def on_created(self, e):
        if not e.is_directory:
            self.rt.enqueue(e.src_path, "file", "New file in a watched folder")

    def on_modified(self, e):
        if not e.is_directory:
            self.rt.enqueue(e.src_path, "file", "Changed file in a watched folder")

    def on_moved(self, e):
        if not e.is_directory:
            self.rt.enqueue(e.dest_path, "file", "File saved in a watched folder")


_CANARY_STRIKES: dict[str, list[float]] = collections.defaultdict(list)


class RealTime:
    def __init__(self):
        self.lock = threading.RLock()
        self.stop_evt = threading.Event()
        self.running = False
        self.started = None
        self.pending: dict[str, dict] = {}
        self.cache: collections.OrderedDict = collections.OrderedDict()
        self.observer = None
        self._ex, self._ex_time = None, 0.0
        self._yara, self._yara_sig = None, None
        self.stats, self.comp = {}, {}

    def start(self):
        with self.lock:
            if self.running:
                return
            self.stop_evt = threading.Event()
            self.running, self.started = True, now()
            self.stats = dict(files_scanned=0, processes_checked=0, threats=0, stopped=0, skipped_busy=0, errors=0)
            self.comp = {"antivirus": {"state": "starting", "msg": ""}, "yara": {"state": "starting", "msg": ""},
                         "sysmon": {"state": "starting", "msg": "", "events": 0, "last": None},
                         "watcher": {"state": "starting", "msg": "", "folders": []},
                         "sigma": {"state": "starting", "msg": "", "last_run": None, "duration": None, "found": 0}}
            ev = self.stop_evt
            for f in (self._scanner_loop, self._sysmon_loop, self._defender_loop, self._watch_loop, self._sigma_loop):
                threading.Thread(target=f, args=(ev,), daemon=True, name=f.__name__).start()
        log.info("Real-time protection started")

    def stop(self):
        with self.lock:
            if not self.running:
                return
            self.stop_evt.set()
            self.running = False
            if self.observer is not None:
                try:
                    self.observer.stop()
                except Exception:
                    pass
                self.observer = None
            self.pending.clear()
        log.info("Real-time protection stopped")

    def restart(self):
        if self.running:
            self.stop()
            time.sleep(0.5)
            self.start()

    def status(self) -> dict:
        with self.lock:
            return {"enabled": self.running, "started": self.started, "queue": len(self.pending),
                    "stats": dict(self.stats), "components": json.loads(json.dumps(self.comp)),
                    "auto_stop": bool(CFG.get("rt_auto_stop"))}

    def _set(self, name, **kw):
        with self.lock:
            self.comp.setdefault(name, {}).update(kw)

    def _inc(self, k, n=1):
        with self.lock:
            self.stats[k] = self.stats.get(k, 0) + n

    def excl(self) -> Exclusions:
        if self._ex is None or time.time() - self._ex_time > 30:
            self._ex, self._ex_time = Exclusions(), time.time()
        return self._ex

    def own(self, path: str) -> bool:
        if not path:
            return False
        n = norm(path)
        if any(n.startswith(d + os.sep) for d in own_dirs()):
            return True
        return os.path.basename(n) in ("sysmon64.exe", "sysmon.exe") and "windows" in n

    def enqueue(self, path: str, kind: str, why: str, ctx: dict | None = None):
        if not self.running or not path:
            return
        if ".sc_canary_" in path.lower():
            writer = ((ctx.get("writer") or "").lower() if ctx else "")
            w_base = os.path.basename(writer) if writer else ""
            benign = {"searchindexer.exe", "onedrive.exe", "msmpeng.exe", "explorer.exe",
                      "robocopy.exe", "dropbox.exe", "googledrivesync.exe", "securityconsole.exe",
                      "backend.exe", "python.exe", "svchost.exe"}
            if w_base in benign or self.own(writer):
                return
            now_t = time.time()
            strike_key = writer or "unknown"
            _CANARY_STRIKES[strike_key] = [t for t in _CANARY_STRIKES[strike_key] if now_t - t < 30]
            _CANARY_STRIKES[strike_key].append(now_t)
            strikes = len(_CANARY_STRIKES[strike_key])
            if strikes == 1:
                emit("watcher", "medium", "Ransomware Canary: Decoy Document Accessed", path,
                     details=f"Canary decoy document was accessed/modified by '{w_base or 'process'}'. Monitoring process activity.",
                     uniq=f"canary|first|{path}|{int(now_t // 30)}", origin="realtime", mitre="T1486 - Data Encrypted for Impact (Impact)")
            else:
                emit("watcher", "critical", "Ransomware Canary Alert: Multi-Canary Rapid Modification", path,
                     details=f"Multiple canary decoys ({strikes} hits) modified rapidly by '{w_base or 'unidentified process'}'. Probable active ransomware attack.",
                     uniq=f"canary|crit|{int(now_t // 15)}", origin="realtime", mitre="T1486 - Data Encrypted for Impact (Impact)")
            return
        path = os.path.normpath(path)
        ext = os.path.splitext(path)[1].lower()
        if ext in PARTIAL_EXT or (kind == "file" and ext not in RISKY_EXT):
            return
        if self.own(path) or self.excl().file(path):
            return
        key = norm(path)
        settle = 0.0 if kind == "process" else float(CFG.get("rt_settle_seconds", 1.5))
        with self.lock:
            item = self.pending.get(key)
            if item:
                item["due"] = time.time() + settle
                if kind == "process":
                    item.update(kind="process", why=why, ctx=ctx or {})
                return
            if len(self.pending) >= 5000:
                self.stats["skipped_busy"] += 1
                return
            self.pending[key] = {"path": path, "kind": kind, "why": why, "ctx": ctx or {},
                                 "due": time.time() + settle, "tries": 0}

    def _yara_rules(self):
        rules_dir = pathlib.Path(CFG["yara_rules"]).parent
        try:
            sig = max((p.stat().st_mtime for p in rules_dir.rglob("*.yar*")), default=0)
        except OSError:
            sig = 0
        if self._yara is None or sig != self._yara_sig:
            self._yara, self._yara_sig = prepare_yara("rules_rt.yarc"), sig
        return self._yara

    def _scanner_loop(self, stop):
        while not stop.wait(0.4):
            try:
                self._scan_due()
            except Exception as e:
                log.exception("real-time scanner")
                self._inc("errors")
                self._set("antivirus", msg=f"Scanner error: {e}")

    def _scan_due(self):
        t = time.time()
        with self.lock:
            keys = [k for k, v in self.pending.items() if v["due"] <= t][:64]
            due = [self.pending.pop(k) for k in keys]
        ready = []
        max_bytes = int(CFG.get("rt_max_file_mb", 150)) * 1024 * 1024
        for it in due:
            p = it["path"]
            try:
                st = os.stat(p)
            except OSError:
                continue
            if not os.path.isfile(p) or st.st_size == 0 or st.st_size > max_bytes:
                continue
            busy = it["kind"] == "file" and time.time() - st.st_mtime < 1.0
            if not busy:
                try:
                    with open(p, "rb"):
                        pass
                except PermissionError:
                    busy = True
                except OSError:
                    continue
            if busy and it["tries"] < 10:
                it["tries"] += 1
                it["due"] = time.time() + 1.0
                with self.lock:
                    self.pending.setdefault(norm(p), it)
                continue
            key = (norm(p), st.st_size, st.st_mtime_ns)
            if key in self.cache:
                self.cache.move_to_end(key)
                if it["kind"] == "process":
                    self._inc("processes_checked")
                continue
            ready.append((it, key))
        if ready:
            self._scan(ready)

    def _scan(self, ready: list):
        findings: dict[str, list] = {}
        av = clamd_ping()
        self._set("antivirus", state="running" if av else "off",
                  msg="" if av else "The ClamAV service isn't answering - only pattern rules are used.")
        if av:
            for it, _ in ready:
                status, sig = clamd_scan(it["path"])
                if status == "found":
                    findings.setdefault(os.path.normpath(it["path"]), []).append(("clamav", sig, explain_clamav(sig)))
                elif status == "error":
                    self._inc("errors")
        yr = self._yara_rules()
        self._set("yara", state="running" if yr else "off", msg="" if yr else "yara64.exe or the rules are missing")
        if yr:
            lst = BASE / "data" / "rt_scan.lst"
            lst.write_text("\n".join(it["path"] for it, _ in ready) + "\n", encoding="utf-8")
            hits, _ = yara_batch(str(lst), *yr)
            for rule, meta, path in hits:
                findings.setdefault(os.path.normpath(path), []).append(("yara", rule, explain_yara(rule, meta)))
            if CFG.get("rt_scan_process_memory"):
                for it, _ in ready:
                    pid = str(it["ctx"].get("pid", ""))
                    if it["kind"] == "process" and pid.isdigit():
                        args = [CFG["yara"], "-w", "-m", "-a", "30"] + (["-C"] if yr[1] else []) + [yr[0], pid]
                        for line in run(args, timeout=120).stdout.splitlines():
                            m = re.match(r"^(\S+) \[(.*)\] \d+$", line)
                            if m:
                                meta = {k: v.strip('"') for k, v in YARA_META.findall(m.group(2))}
                                findings.setdefault(os.path.normpath(it["path"]), []).append(
                                    ("yara", m.group(1) + " (in memory)", explain_yara(m.group(1), meta)))
        for it, key in ready:
            self.cache[key] = True
            if len(self.cache) > 50000:
                self.cache.popitem(last=False)
            self._inc("processes_checked" if it["kind"] == "process" else "files_scanned")
            hits = findings.get(os.path.normpath(it["path"]))
            if hits:
                self._report(it, hits)

    def _report(self, it: dict, hits: list):
        path, ctx = it["path"], it["ctx"]
        digest = sha256(path)
        extra = []
        stopped = False
        if it["kind"] == "process":
            pid = str(ctx.get("pid", ""))
            dangerous = any(info["severity"] in ("critical", "high") for _, _, info in hits)
            if CFG.get("rt_auto_stop") and dangerous and pid.isdigit() and not protected_reason(path):
                try:
                    stopped = bool(stop_pid(int(pid)).get("stopped"))
                except Exception as e:
                    extra.append(f"auto-stop failed: {e}")
            extra.append(f"Program started (PID {pid})")
            if ctx.get("parent"):
                extra.append(f"started by {os.path.basename(ctx['parent'])}")
            if ctx.get("user"):
                extra.append(f"user {ctx['user']}")
            if ctx.get("cmd"):
                extra.append(f"command: {ctx['cmd'][:300]}")
            if not stopped:
                extra.append(self._connections(pid))
        else:
            extra.append(it["why"])
            if ctx.get("writer"):
                extra.append(f"created by {os.path.basename(ctx['writer'])}")
        for engine, rule, info in hits:
            details = f"{info['what']} [Real-time: {'; '.join(x for x in extra if x)}]"
            if emit(engine, info["severity"], rule, path, details=details,
                    uniq=f"{engine}|{rule}|{path}|{digest}", origin="realtime"):
                self._inc("threats")
        if stopped:
            self._inc("stopped")
            emit("console", "medium", "Dangerous program was stopped automatically", path,
                 details=f"Real-time protection stopped '{os.path.basename(path)}' as soon as it started. "
                         "The file is still there - quarantine or block it from the Threats page.",
                 uniq=f"autostop|{path}|{digest}|{int(time.time())}", origin="realtime")

    def _connections(self, pid: str) -> str:
        if not pid.isdigit():
            return ""
        try:
            rows = osquery("SELECT DISTINCT s.remote_address, s.remote_port, s.local_port FROM process_open_sockets s "
                           f"WHERE s.pid = {int(pid)};")
        except Exception as e:
            return f"network: couldn't check ({e})"
        conns = [f"{r.get('remote_address')}:{r.get('remote_port')}" for r in rows
                 if str(r.get("remote_port", "0")) not in ("0", "") and r.get("remote_address") not in ("", "0.0.0.0", "::")]
        listen = [str(r.get("local_port")) for r in rows if str(r.get("remote_port", "0")) in ("0", "")]
        parts = (["connected to " + ", ".join(conns[:10])] if conns else []) + \
                (["listening on port " + ", ".join(sorted(set(listen))[:10])] if listen else [])
        return "network: " + ("; ".join(parts) if parts else "no open connections")

    def _sysmon_loop(self, stop):
        reader = SysmonReader()
        if reader.method is None:
            self._set("sysmon", state="off", msg="Windows event log isn't available")
            return
        while not stop.is_set():
            try:
                if reader.last is None:
                    reader.open()
                    self._set("sysmon", state="running", msg="")
                for ev in reader.poll():
                    self._on_sysmon(ev)
            except Exception as e:
                reader.last = None
                self._set("sysmon", state="off", msg=f"Can't read Sysmon events - is Sysmon running? ({str(e)[:120]})")
                stop.wait(15)
                continue
            stop.wait(1.0)

    def _on_sysmon(self, ev: dict):
        with self.lock:
            self.comp["sysmon"]["events"] = self.comp["sysmon"].get("events", 0) + 1
            self.comp["sysmon"]["last"] = now()
        if ev["EventID"] == 11:
            if not self.own(ev.get("Image", "")):
                self.enqueue(ev.get("TargetFilename", ""), "file", "New file (Sysmon)", {"writer": ev.get("Image", "")})
        elif ev["EventID"] == 1:
            image, parent = ev.get("Image", ""), ev.get("ParentImage", "")
            pid = ev.get("ProcessId", "")
            row = blocked_match(image)
            if row and pid.isdigit():  # blocked program: stop it right away
                if enforce_block(int(pid), image, row):
                    self._inc("stopped")
                return
            if self.own(image) or self.own(parent):
                return
            h = re.search(r"SHA256=([0-9A-Fa-f]{64})", ev.get("Hashes", ""))
            self.enqueue(image, "process", "New program (Sysmon)",
                         {"pid": pid, "parent": parent, "cmd": ev.get("CommandLine", ""),
                          "user": ev.get("User", ""), "sha256": h.group(1) if h else ""})

    def _defender_loop(self, stop):
        reader = DefenderReader()
        if reader.method is None:
            return
        while not stop.is_set():
            try:
                if reader.last is None:
                    reader.open()
                for ev in reader.poll():
                    self._on_defender(ev)
            except Exception as e:
                reader.last = None
                stop.wait(20)
                continue
            stop.wait(2.0)

    def _on_defender(self, ev: dict):
        eid = ev.get("EventID")
        path = ev.get("Path") or ev.get("TargetFilename") or ev.get("ProcessName") or ""
        threat = ev.get("ThreatName") or ev.get("RuleName") or "Suspicious Activity"
        if eid == 1116:
            emit("defender", "high", f"Microsoft Defender: {threat}", path,
                 details=f"Defender detected threat '{threat}' at {path}.",
                 origin="defender", mitre="T1204 - User Execution")
        elif eid == 1117:
            emit("defender", "medium", f"Microsoft Defender Action: {threat}", path,
                 details=f"Defender took protective action on {path}.",
                 origin="defender", mitre="T1204 - User Execution")
        elif eid == 1121:
            emit("defender", "high", f"ASR Exploit Guard Blocked: {threat}", path,
                 details=f"Attack Surface Reduction blocked an operation. Rule: {threat}. Target: {path}",
                 origin="defender", mitre="T1059 - Command and Scripting Interpreter")
        elif eid == 1122:
            emit("defender", "low", f"ASR Exploit Guard Audit: {threat}", path,
                 details=f"Attack Surface Reduction logged an audited operation. Rule: {threat}. Target: {path}",
                 origin="defender", mitre="T1059 - Command and Scripting Interpreter")

    def watch_folders(self) -> list[str]:
        folders = quick_targets() + [os.path.expandvars(p) for p in CFG.get("rt_extra_folders", [])]
        return [f for f in dict.fromkeys(folders) if os.path.isdir(f) and not self.excl().path(f)]

    def _watch_loop(self, stop):
        folders = self.watch_folders()
        if Observer is not None:
            try:
                obs = Observer()
                handler = _WatchHandler(self)
                for f in folders:
                    obs.schedule(handler, f, recursive=True)
                obs.daemon = True
                obs.start()
                with self.lock:
                    self.observer = obs
                self._set("watcher", state="running", folders=folders, msg="")
                stop.wait()
                return
            except Exception as e:
                log.exception("watchdog failed, polling instead")
                self._set("watcher", msg=f"Fast watcher failed ({e}); checking every 5 seconds instead")
        self._set("watcher", state="running", folders=folders, msg="Checking folders every 5 seconds")
        seen: dict[str, float] = {}
        first = True
        while not stop.is_set():
            for root in folders:
                base_depth = root.rstrip("\\/").count(os.sep)
                for d, dirs, files in os.walk(root):
                    if d.count(os.sep) - base_depth >= 2:
                        dirs[:] = []
                    for fn in files:
                        p = os.path.join(d, fn)
                        try:
                            m = os.stat(p).st_mtime
                        except OSError:
                            continue
                        if seen.get(p) != m:
                            if not first:
                                self.enqueue(p, "file", "New file in a watched folder")
                            seen[p] = m
            first = False
            stop.wait(5)

    def _sigma_loop(self, stop):
        while not stop.is_set():
            interval = max(30, int(CFG.get("rt_sigma_seconds", 60)))
            t0 = time.time()
            if not pathlib.Path(CFG["hayabusa"]).exists():
                self._set("sigma", state="off", msg="hayabusa.exe is missing")
                stop.wait(60)
                continue
            if not _HB_LOCK.acquire(timeout=1):
                self._set("sigma", msg="Waiting for the full event log check to finish")
                stop.wait(5)
                continue
            try:
                n = self.sigma_once((interval * 2 + 30) * 1000)
                self._set("sigma", state="running", msg="", last_run=now(), duration=round(time.time() - t0, 1), found=n)
            except Exception as e:
                log.exception("real-time sigma")
                self._set("sigma", state="error", msg=str(e)[:300], last_run=now())
            finally:
                _HB_LOCK.release()
            stop.wait(max(10, interval - (time.time() - t0)))

    def sigma_once(self, window_ms: int) -> int:
        d = BASE / "data" / "rt_evtx"
        d.mkdir(parents=True, exist_ok=True)
        for f in d.glob("*.evtx"):
            f.unlink(missing_ok=True)
        exported = 0
        for ch in CFG.get("rt_channels", []):
            try:
                if export_recent_events(ch, d / (re.sub(r"[^A-Za-z0-9]+", "_", ch) + ".evtx"), window_ms):
                    exported += 1
            except Exception:
                pass
        if not exported:
            raise RuntimeError("Couldn't read any event logs")
        out = BASE / "data" / "rt_sigma.jsonl"
        hayabusa_timeline(["-d", str(d)], out, timeout=300)
        n = ingest_hayabusa(out, origin="realtime")
        self._inc("threats", n)
        return n


RT = RealTime()

# --------------------------------------------------------------------------- #
# PAUSE / RESUME / EXIT  ("stop everything" button)
# --------------------------------------------------------------------------- #
PAUSE_SERVICES = ("clamav", "freshclam", "sysmon", "osquery")
_PAUSE_LOCK = threading.Lock()


def pause_state() -> dict:
    until = get_setting("paused_until", "")
    if not until:
        return {"paused": False}
    return {"paused": True, "until": None if until == "forever" else until,
            "since": get_setting("paused_since", ""), "services": json.loads(get_setting("paused_services", "[]") or "[]")}


def is_paused() -> bool:
    return bool(get_setting("paused_until", ""))


def _svc(action: str, name: str):
    if os.name != "nt" or not name:
        return
    try:
        run(["sc", action, name], timeout=60)
    except Exception:
        log.exception("sc %s %s", action, name)


def _stop_services() -> list[str]:
    stopped = []
    for key in PAUSE_SERVICES:
        name = CFG["services"].get(key)
        if name and svc_state(name) == "running":
            _svc("stop", name)
            stopped.append(name)
    return stopped


def pause_all(minutes: int | None) -> dict:
    with _PAUSE_LOCK:
        if not is_paused():
            set_setting("rt_before_pause", "1" if RT.running else "0")
        RT.stop()
        stopped = _stop_services()
        prev = set(json.loads(get_setting("paused_services", "[]") or "[]"))
        set_setting("paused_services", json.dumps(sorted(prev | set(stopped))))
        until = "forever" if not minutes else (dt.datetime.now() + dt.timedelta(minutes=int(minutes))).isoformat(timespec="seconds")
        set_setting("paused_until", until)
        set_setting("paused_since", now())
    how = "until you turn it back on" if until == "forever" else f"for {minutes} minutes"
    emit("console", "medium", "Protection paused", "Security Console",
         details=f"All protection was paused {how}. Stopped: {', '.join(stopped) or 'no running services'}.",
         uniq=f"pause|{now()}")
    return pause_state()


def resume_all(reason: str = "You turned protection back on.") -> dict:
    with _PAUSE_LOCK:
        if not is_paused():
            return pause_state()
        names = json.loads(get_setting("paused_services", "[]") or "[]")
        # always bring back the core services, even if they were stopped before the pause
        for key in ("clamav", "freshclam", "sysmon"):
            n = CFG["services"].get(key)
            if n and n not in names:
                names.append(n)
        for n in names:
            if svc_state(n) == "stopped":
                _svc("start", n)
        set_setting("paused_until", "")
        set_setting("paused_services", "[]")
        if get_setting("rt_before_pause", "0") == "1":
            RT.start()
    emit("console", "low", "Protection resumed", "Security Console", details=reason, uniq=f"resume|{now()}")
    return pause_state()


def pause_watchdog():
    """Auto-resume when the pause time is over; keep services stopped while paused (e.g. after a reboot)."""
    first = True
    while True:
        try:
            st = pause_state()
            if st["paused"]:
                if st.get("until") and dt.datetime.now() >= dt.datetime.fromisoformat(st["until"]):
                    resume_all("The pause time ended, so protection turned back on automatically.")
                elif first:
                    RT.stop()
                    _stop_services()
        except Exception:
            log.exception("pause watchdog")
        first = False
        time.sleep(15)


def exit_app():
    """Stop the Security Console background program itself (and stop it restarting)."""
    log.info("Exit requested from the dashboard")
    RT.stop()
    if os.name == "nt":
        cmd = ('ping -n 3 127.0.0.1 >nul & schtasks /End /TN "SecurityConsole" >nul 2>&1 & '
               'sc stop SecurityConsole >nul 2>&1 & taskkill /F /PID ' + str(os.getpid()) + ' >nul 2>&1')
        flags = 0x00000008 | 0x00000200 | 0x01000000 | NO_WINDOW  # detached, new group, breakaway from job
        try:
            subprocess.Popen(["cmd.exe", "/c", cmd], creationflags=flags, close_fds=True)
            return
        except Exception:
            log.exception("detached exit failed")
    threading.Timer(1.5, lambda: os._exit(0)).start()


# --------------------------------------------------------------------------- #
# SYSTEM INFO (PC specs + live monitor)
# --------------------------------------------------------------------------- #
SYSINFO_PS = r'''
# SecurityConsole internal (sc-internal): reads PC specs
$ErrorActionPreference = "SilentlyContinue"
function D($d) { if ($d) { try { ([datetime]$d).ToString("o") } catch { "$d" } } else { $null } }
$o = [ordered]@{}
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$o.computer = [ordered]@{ name = $env:COMPUTERNAME; manufacturer = $cs.Manufacturer; model = $cs.Model; type = $cs.SystemType;
  domain = $cs.Domain; user = $cs.UserName; ram = [int64]$cs.TotalPhysicalMemory }
$o.os = [ordered]@{ name = $os.Caption; version = $cv.DisplayVersion; build = "$($os.BuildNumber).$($cv.UBR)"; arch = $os.OSArchitecture;
  installed = D $os.InstallDate; boot = D $os.LastBootUpTime; owner = $os.RegisteredUser }
$o.cpu = @(Get-CimInstance Win32_Processor | ForEach-Object { [ordered]@{ name = $_.Name.Trim(); cores = $_.NumberOfCores;
  threads = $_.NumberOfLogicalProcessors; max_mhz = $_.MaxClockSpeed; l2_kb = $_.L2CacheSize; l3_kb = $_.L3CacheSize;
  socket = $_.SocketDesignation; virtualization = $_.VirtualizationFirmwareEnabled; maker = $_.Manufacturer } })
$vram = @{}
Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" | ForEach-Object {
  if ($_.DriverDesc -and $_."HardwareInformation.qwMemorySize") { $vram[$_.DriverDesc] = [int64]$_."HardwareInformation.qwMemorySize" } }
$o.gpu = @(Get-CimInstance Win32_VideoController | ForEach-Object { [ordered]@{ name = $_.Name; driver = $_.DriverVersion;
  driver_date = D $_.DriverDate; vram = $(if ($vram[$_.Name]) { $vram[$_.Name] } else { [int64]$_.AdapterRAM });
  resolution = $(if ($_.CurrentHorizontalResolution) { "$($_.CurrentHorizontalResolution) x $($_.CurrentVerticalResolution)" });
  refresh = $_.CurrentRefreshRate; processor = $_.VideoProcessor } })
$o.memory = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { [ordered]@{ slot = $_.DeviceLocator; size = [int64]$_.Capacity;
  speed = $(if ($_.ConfiguredClockSpeed) { $_.ConfiguredClockSpeed } else { $_.Speed }); maker = "$($_.Manufacturer)".Trim();
  part = "$($_.PartNumber)".Trim(); type = $_.SMBIOSMemoryType } })
$o.memory_slots = (Get-CimInstance Win32_PhysicalMemoryArray | Measure-Object MemoryDevices -Sum).Sum
$pd = @(Get-PhysicalDisk | ForEach-Object { [ordered]@{ name = $_.FriendlyName; media = "$($_.MediaType)"; bus = "$($_.BusType)";
  size = [int64]$_.Size; health = "$($_.HealthStatus)" } })
if (-not $pd.Count) { $pd = @(Get-CimInstance Win32_DiskDrive | ForEach-Object { [ordered]@{ name = $_.Model; media = $_.MediaType; bus = $_.InterfaceType; size = [int64]$_.Size; health = $_.Status } }) }
$o.disks = $pd
$bb = Get-CimInstance Win32_BaseBoard; $bi = Get-CimInstance Win32_BIOS
$o.board = [ordered]@{ maker = $bb.Manufacturer; model = $bb.Product; bios = $bi.SMBIOSBIOSVersion; bios_maker = $bi.Manufacturer;
  bios_date = D $bi.ReleaseDate; serial = $bi.SerialNumber }
$o.network = @(Get-NetAdapter -Physical | ForEach-Object { $a = $_
  $ip = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Select-Object -First 1
  $cfg = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex
  [ordered]@{ name = $a.Name; desc = $a.InterfaceDescription; status = "$($a.Status)"; speed = $a.LinkSpeed; mac = $a.MacAddress;
    ip = $ip.IPAddress; gateway = $cfg.IPv4DefaultGateway.NextHop; dns = (@($cfg.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) -join ", ") } })
$w = netsh wlan show interfaces 2>$null
if ($w) { $ssid = ($w | Select-String '^\s*SSID\s*:\s*(.+)$' | Select-Object -First 1).Matches.Groups[1].Value
  $sig = ($w | Select-String '^\s*Signal\s*:\s*(.+)$' | Select-Object -First 1).Matches.Groups[1].Value
  if ($ssid) { $o.wifi = [ordered]@{ ssid = $ssid.Trim(); signal = "$sig".Trim() } } }
$mp = Get-MpComputerStatus
$fw = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = $_.Name; on = [bool]$_.Enabled } })
$sb = $null; try { $sb = Confirm-SecureBootUEFI } catch {}
$tpm = $null; try { $t = Get-Tpm; $tpm = [ordered]@{ present = $t.TpmPresent; ready = $t.TpmReady } } catch {}
$bl = $null; try { $bl = "$((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus)" } catch {}
$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$o.security = [ordered]@{ defender_on = $mp.AntivirusEnabled; defender_rt = $mp.RealTimeProtectionEnabled;
  defender_sigs = D $mp.AntivirusSignatureLastUpdated; defender_tamper = $mp.IsTamperProtected; firewall = $fw; secure_boot = $sb;
  tpm = $tpm; bitlocker = $bl; last_update = D $hf.InstalledOn; last_update_id = $hf.HotFixID; uac = [bool]((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA) }
$o | ConvertTo-Json -Depth 6 -Compress
'''

GPU_PS = r'''
# SecurityConsole internal (sc-internal): GPU usage
$ErrorActionPreference = "SilentlyContinue"
while ($true) {
  $u = (Get-Counter '\GPU Engine(*engtype_3D)\Utilization Percentage').CounterSamples | Measure-Object CookedValue -Sum
  $m = (Get-Counter '\GPU Adapter Memory(*)\Dedicated Usage').CounterSamples | Measure-Object CookedValue -Sum
  [Console]::Out.WriteLine((@{ util = [math]::Round($u.Sum, 1); mem = [int64]$m.Sum } | ConvertTo-Json -Compress))
  [Console]::Out.Flush()
  Start-Sleep -Milliseconds 1500
}
'''

_SYSINFO = {"data": None, "time": 0.0, "lock": threading.Lock()}


def system_info(refresh: bool = False) -> dict:
    with _SYSINFO["lock"]:
        if _SYSINFO["data"] and not refresh and time.time() - _SYSINFO["time"] < 600:
            return _SYSINFO["data"]
        data = {}
        if os.name == "nt":
            try:
                r = run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", SYSINFO_PS], timeout=90)
                data = json.loads(r.stdout.strip() or "{}")
            except Exception as e:
                log.exception("system info")
                data = {"error": str(e)}
        else:  # development fallback
            import platform
            data = {"computer": {"name": socket.gethostname(), "manufacturer": "", "model": platform.machine(),
                                 "ram": psutil.virtual_memory().total if psutil else 0},
                    "os": {"name": f"{platform.system()} {platform.release()}", "build": platform.version()[:40], "arch": platform.machine(),
                           "boot": dt.datetime.fromtimestamp(psutil.boot_time()).isoformat() if psutil else None},
                    "cpu": [{"name": platform.processor() or "CPU", "cores": psutil.cpu_count(False) if psutil else 0,
                             "threads": psutil.cpu_count() if psutil else 0}], "gpu": [], "memory": [], "disks": [], "network": []}
        for k in ("cpu", "gpu", "memory", "disks", "network"):  # PowerShell returns a lone item as an object
            if isinstance(data.get(k), dict):
                data[k] = [data[k]]
        _SYSINFO.update(data=data, time=time.time())
        return data


class GpuSampler:
    def __init__(self):
        self.last_req = 0.0
        self.proc = None
        self.data = {}
        self.lock = threading.Lock()
        self.nvsmi = next((p for p in (r"C:\Windows\System32\nvidia-smi.exe",
                                       r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe") if os.path.exists(p)), None)

    def get(self) -> dict:
        self.last_req = time.time()
        with self.lock:
            if self.proc is None and os.name == "nt":
                threading.Thread(target=self._loop, daemon=True).start()
                self.proc = "starting"
            return dict(self.data)

    def _loop(self):
        try:
            self.proc = subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-Command", GPU_PS],
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, creationflags=NO_WINDOW)
            remember_pid(self.proc.pid)
            for line in self.proc.stdout:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                d["util"] = min(100.0, float(d.get("util") or 0))
                if self.nvsmi:
                    try:
                        r = run([self.nvsmi, "--query-gpu=temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,fan.speed",
                                 "--format=csv,noheader,nounits"], timeout=10)
                        v = [x.strip() for x in r.stdout.splitlines()[0].split(",")]
                        num = lambda x: float(x) if x.replace(".", "", 1).isdigit() else None
                        d.update(temp=num(v[0]), util=num(v[1]) if num(v[1]) is not None else d["util"],
                                 mem=int(num(v[2]) * 1048576) if num(v[2]) else d.get("mem"),
                                 mem_total=int(num(v[3]) * 1048576) if num(v[3]) else None, power=num(v[4]), fan=num(v[5]))
                    except Exception:
                        pass
                with self.lock:
                    self.data = d
                if time.time() - self.last_req > 30:  # nobody is watching: stop sampling
                    break
        except Exception:
            log.exception("gpu sampler")
        finally:
            try:
                self.proc.kill()
            except Exception:
                pass
            with self.lock:
                self.proc = None


GPU = GpuSampler()
# --------------------------------------------------------------------------- #
# v1.7: overview, network connections, startup on/off
# --------------------------------------------------------------------------- #
import ipaddress


def defs_info() -> dict:
    d = pathlib.Path(CFG["clamscan"]).parent / "database"
    try:
        files = [p for p in d.iterdir() if p.suffix.lower() in (".cvd", ".cld", ".cud")]
    except OSError:
        files = []
    if not files:
        return {"updated": None, "age_hours": None}
    t = max(p.stat().st_mtime for p in files)
    return {"updated": dt.datetime.fromtimestamp(t).isoformat(timespec="seconds"), "age_hours": round((time.time() - t) / 3600, 1)}


def overview() -> dict:
    with db() as con:
        r = con.execute("SELECT * FROM jobs WHERE kind='scan' AND state IN ('done','cancelled') AND target!='Protection self-test' "
                        "ORDER BY finished DESC LIMIT 1").fetchone()
    last = None
    if r:
        res = json.loads(r["result"] or "{}")
        last = {"time": r["finished"], "label": r["target"], "found": res.get("found", 0),
                "files": (res.get("stats") or {}).get("scanned", 0), "verdict": res.get("verdict")}
    sec = (_SYSINFO.get("data") or {}).get("security") or {}
    return {"last_scan": last, "defs": defs_info(), "realtime": RT.running, "pause": pause_state(),
            "defender": {"on": sec.get("defender_on"), "rt": sec.get("defender_rt"), "sigs": sec.get("defender_sigs")} if sec else None}


def ip_scope(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "internet"
    if a.is_loopback:
        return "this-pc"
    if a.is_private or a.is_link_local:
        return "local"
    return "internet"


def network_connections() -> dict:
    if not psutil:
        raise RuntimeError("psutil isn't available")
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        raise RuntimeError("Windows didn't allow reading network connections")
    groups: dict = {}
    names: dict = {}
    fw = {norm(r["path"]): r for r in blocked_rows() if r["firewall"]}
    for c in conns:
        pid = c.pid or 0
        if pid not in names:
            try:
                p = psutil.Process(pid)
                names[pid] = (p.name(), p.exe() or "")
            except (psutil.Error, OSError):
                names[pid] = ("System" if pid in (0, 4) else f"PID {pid}", "")
        name, exe = names[pid]
        key = (exe or name).lower()
        g = groups.setdefault(key, {"name": name, "path": exe, "pids": set(), "remotes": [], "listening": set(), "udp": 0})
        g["pids"].add(pid)
        if c.status == psutil.CONN_LISTEN:
            g["listening"].add((c.laddr.port, c.laddr.ip))
        elif c.raddr:
            g["remotes"].append({"ip": c.raddr.ip, "port": c.raddr.port, "status": c.status.replace("_", " ").title(),
                                 "scope": ip_scope(c.raddr.ip), "local_port": c.laddr.port if c.laddr else None})
        elif c.type == socket.SOCK_DGRAM:
            g["udp"] += 1
    out = []
    for g in groups.values():
        inet = [r for r in g["remotes"] if r["scope"] == "internet"]
        seen, uniq = set(), []
        for r in sorted(g["remotes"], key=lambda r: (r["scope"] != "internet", r["ip"])):
            k = (r["ip"], r["port"])
            if k not in seen:
                seen.add(k)
                uniq.append(r)
        out.append({"name": g["name"], "path": g["path"], "pids": sorted(g["pids"]), "connections": len(g["remotes"]),
                    "internet": len(inet), "internet_hosts": len({r["ip"] for r in inet}), "remotes": uniq[:200],
                    "listening": sorted({p for p, _ in g["listening"]}),
                    "open_to_network": any(not ip.startswith(("127.", "::1")) for _, ip in g["listening"]),
                    "firewall_blocked": norm(g["path"]) in fw if g["path"] else False,
                    "system": not g["path"] or bool(protected_reason(g["path"])) or under(g["path"], str(BASE)),
                    "self": bool(g["path"]) and any(under(g["path"], d) for d in own_dirs())})
    out.sort(key=lambda g: (-g["internet"], -g["connections"], g["name"].lower()))
    tot = {"programs_online": sum(1 for g in out if g["internet"]), "internet": sum(g["internet"] for g in out),
           "connections": sum(g["connections"] for g in out), "listening": sum(len(g["listening"]) for g in out)}
    return {"summary": tot, "programs": out}


# ---- startup items on/off (same switch Task Manager uses) ------------------ #
SA_BASE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"


def _sid_for_profile(path: str) -> str | None:
    import winreg
    key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
        for i in range(winreg.QueryInfoKey(k)[0]):
            sid = winreg.EnumKey(k, i)
            try:
                with winreg.OpenKey(k, sid) as sk:
                    prof = os.path.expandvars(winreg.QueryValueEx(sk, "ProfileImagePath")[0])
                if under(path, prof):
                    return sid
            except OSError:
                continue
    return None


def startup_location(name: str, source: str, path: str = ""):
    """Return (hive, subkey, value_name) of the StartupApproved entry for a startup item, or None."""
    import winreg
    s = (source or "").replace("/", "\\")
    low = s.lower()
    if low.endswith("\\runonce") or "\\runonce\\" in low:
        return None
    if "\\run" in low and low.startswith(("hkey_local_machine", "hklm")):
        sub = "Run32" if "wow6432node" in low else "Run"
        return winreg.HKEY_LOCAL_MACHINE, f"{SA_BASE}\\{sub}", name
    m = re.match(r"(?:hkey_users|hku)\\([^\\]+)\\", low)
    if m and "\\run" in low:
        sid = s.split("\\")[1]
        sub = "Run32" if "wow6432node" in low else "Run"
        return winreg.HKEY_USERS, f"{sid}\\{SA_BASE}\\{sub}", name
    if "startup" in low and (":" in s or low.startswith("\\\\")):
        folder = s if os.path.isdir(s) else os.path.dirname(path or s)
        fname = os.path.basename(path) if path and os.path.splitext(path)[1] else name
        if under(folder, os.path.expandvars(r"%ProgramData%")):
            return winreg.HKEY_LOCAL_MACHINE, f"{SA_BASE}\\StartupFolder", fname
        sid = _sid_for_profile(folder)
        if sid:
            return winreg.HKEY_USERS, f"{sid}\\{SA_BASE}\\StartupFolder", fname
    return None


def startup_enabled(name: str, source: str, path: str = ""):
    if os.name != "nt":
        return None
    import winreg
    try:
        loc = startup_location(name, source, path)
        if not loc:
            return None
        hive, sub, val = loc
        with winreg.OpenKey(hive, sub) as k:
            data, _ = winreg.QueryValueEx(k, val)
        return not (isinstance(data, bytes) and data[:1] in (b"\x01", b"\x03"))
    except OSError:
        return True  # no entry = enabled
    except Exception:
        return None


def set_startup(name: str, source: str, path: str, enable: bool):
    if os.name != "nt":
        raise RuntimeError("Only available on Windows")
    import winreg
    loc = startup_location(name, source, path)
    if not loc:
        raise RuntimeError("This kind of startup item can't be switched off here. Use Task Manager > Startup apps.")
    hive, sub, val = loc
    if enable:
        data = b"\x02" + b"\x00" * 11
    else:
        ft = int((time.time() + 11644473600) * 10_000_000)
        data = b"\x03\x00\x00\x00" + struct.pack("<Q", ft)
    with winreg.CreateKeyEx(hive, sub, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
        winreg.SetValueEx(k, val, 0, winreg.REG_BINARY, data)
    emit("console", "low", "Startup program turned " + ("on" if enable else "off"), name,
         details=f"'{name}' will {'start' if enable else 'no longer start'} automatically when Windows starts.", uniq=f"startup|{name}|{now()}")

_LIVE = {"t": 0.0, "net": None, "disk": None, "procs": {}, "lock": threading.Lock()}


def system_live(lite: bool = False) -> dict:
    if not psutil:
        raise RuntimeError("psutil isn't available")
    with _LIVE["lock"]:
        t = time.time()
        dtime = max(0.5, t - _LIVE["t"]) if _LIVE["t"] else None
        vm, sw = psutil.virtual_memory(), psutil.swap_memory()
        freq = psutil.cpu_freq()
        out = {"time": now(), "uptime": int(t - psutil.boot_time()),
               "cpu": {"percent": psutil.cpu_percent(None), "per_core": psutil.cpu_percent(None, percpu=True),
                       "mhz": round(freq.current) if freq else None, "max_mhz": round(freq.max) if freq and freq.max else None,
                       "processes": len(psutil.pids())},
               "memory": {"total": vm.total, "used": vm.total - vm.available, "available": vm.available, "percent": vm.percent,
                          "swap_total": sw.total, "swap_used": sw.used},
               "gpu": {} if lite else GPU.get()}
        # network + disk throughput
        net, dio = psutil.net_io_counters(pernic=True), psutil.disk_io_counters()
        stats = psutil.net_if_stats()
        tot = {"up": 0, "down": 0}
        nics = []
        for name, c in net.items():
            st = stats.get(name)
            if not st or not st.isup or name.lower().startswith(("loopback", "lo")):
                continue
            prev = (_LIVE["net"] or {}).get(name)
            up = (c.bytes_sent - prev.bytes_sent) / dtime if prev and dtime else 0
            down = (c.bytes_recv - prev.bytes_recv) / dtime if prev and dtime else 0
            tot["up"] += max(0, up)
            tot["down"] += max(0, down)
            nics.append({"name": name, "up": max(0, up), "down": max(0, down), "sent": c.bytes_sent, "recv": c.bytes_recv, "speed": st.speed})
        out["network"] = {"up": tot["up"], "down": tot["down"], "adapters": sorted(nics, key=lambda x: -(x["up"] + x["down"]))}
        prevd = _LIVE["disk"]
        out["disk_io"] = {"read": max(0, (dio.read_bytes - prevd.read_bytes) / dtime) if prevd and dtime and dio else 0,
                          "write": max(0, (dio.write_bytes - prevd.write_bytes) / dtime) if prevd and dtime and dio else 0}
        _LIVE.update(t=t, net=net, disk=dio)
        drives_ = []
        for p in psutil.disk_partitions(all=False):
            if "cdrom" in p.opts or not p.fstype:
                continue
            try:
                u = psutil.disk_usage(p.mountpoint)
            except OSError:
                continue
            drives_.append({"mount": p.mountpoint, "fs": p.fstype, "total": u.total, "used": u.used, "free": u.free, "percent": u.percent})
        out["drives"] = drives_
        try:
            b = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
        except Exception:
            b = None
        out["battery"] = {"percent": b.percent, "plugged": b.power_plugged, "secs": b.secsleft if b.secsleft and b.secsleft > 0 else None} if b else None
        if lite:
            return out
        # top processes (cpu_percent needs two samples, so Process objects are kept between calls)
        cache, seen, procs = _LIVE["procs"], set(), []
        ncpu = psutil.cpu_count() or 1
        for p in psutil.process_iter(["pid", "name", "exe", "memory_info"]):
            pid = p.info["pid"]
            if pid in (0, 4):
                continue
            seen.add(pid)
            proc = cache.get(pid)
            if proc is None:
                cache[pid] = p
                try:
                    p.cpu_percent(None)
                except psutil.Error:
                    pass
                cpu = 0.0
            else:
                try:
                    cpu = proc.cpu_percent(None) / ncpu
                except psutil.Error:
                    continue
            mem = p.info["memory_info"].rss if p.info.get("memory_info") else 0
            procs.append({"pid": pid, "name": p.info["name"] or "?", "path": p.info.get("exe") or "", "cpu": round(cpu, 1), "mem": mem})
        for pid in list(cache):
            if pid not in seen:
                cache.pop(pid, None)
        out["top_cpu"] = sorted(procs, key=lambda x: -x["cpu"])[:8]
        out["top_mem"] = sorted(procs, key=lambda x: -x["mem"])[:8]
        return out


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
app = FastAPI(title="Security Console", version=VERSION)


@app.middleware("http")
async def security_guard_middleware(request: Request, call_next):
    # 1. Host header validation: must be localhost or 127.0.0.1
    host = (request.headers.get("host") or "").split(":")[0].lower()
    if host and host not in ("127.0.0.1", "localhost", "::1"):
        return JSONResponse(status_code=403, content={"detail": "Forbidden: invalid Host header"})

    # 2. Block cross-origin requests from foreign websites
    origin = request.headers.get("origin") or ""
    if origin:
        orig_host = origin.split("://")[-1].split(":")[0].lower()
        if orig_host not in ("127.0.0.1", "localhost"):
            return JSONResponse(status_code=403, content={"detail": "Forbidden: cross-origin access rejected"})

    # 3. Block cross-site fetch/form submission
    if request.headers.get("sec-fetch-site") == "cross-site":
        return JSONResponse(status_code=403, content={"detail": "Forbidden: cross-site requests rejected"})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' data: blob:; connect-src 'self' http://127.0.0.1:8080 http://localhost:8080;"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


class ScanReq(BaseModel):
    targets: list[str] = []
    path: str | None = None
    action: str = "report"
    mode: str = "scan"
    label: str | None = None


class ExclusionReq(BaseModel):
    kind: str = "path"
    value: str
    note: str = ""


class QueryReq(BaseModel):
    sql: str


class PathReq(BaseModel):
    path: str


class StatusReq(BaseModel):
    status: str


class BulkReq(BaseModel):
    ids: list[int]
    status: str


class RealtimeReq(BaseModel):
    enabled: bool


class StopReq(BaseModel):
    pid: int | None = None
    path: str | None = None


class BlockReq(BaseModel):
    path: str
    firewall: bool = False
    run_block: bool = True
    stop_now: bool = True
    note: str = ""


class FirewallReq(BaseModel):
    path: str
    block: bool = True


class MuteReq(BaseModel):
    engine: str = ""
    rule: str
    match: str = ""
    note: str = ""
    event_id: int | None = None


def init_ransomware_canaries():
    """Places hidden decoy files in Documents and Desktop to detect active ransomware encryption."""
    try:
        user_p = os.environ.get("USERPROFILE")
        if user_p:
            for folder in ("Desktop", "Documents"):
                target_dir = os.path.join(user_p, folder)
                if os.path.isdir(target_dir):
                    p = os.path.join(target_dir, ".sc_canary_readme.docx")
                    if not os.path.exists(p):
                        with open(p, "wb") as f:
                            f.write(b"SecurityConsole Canary Decoy Document. Do not delete or encrypt.\n" + os.urandom(512))
                        if os.name == "nt":
                            try:
                                ctypes.windll.kernel32.SetFileAttributesW(p, 0x02) # FILE_ATTRIBUTE_HIDDEN
                            except Exception:
                                pass
    except Exception as e:
        log.debug("Canary init: %s", e)


_BOOTSTRAP_FILE = BASE / "config" / ".auth_bootstrap"
_BOOTSTRAP_TOKEN: str = secrets.token_hex(32)


def _init_bootstrap_token():
    global _BOOTSTRAP_TOKEN
    try:
        _BOOTSTRAP_FILE.parent.mkdir(parents=True, exist_ok=True)
        _BOOTSTRAP_TOKEN = secrets.token_hex(32)
        _BOOTSTRAP_FILE.write_text(_BOOTSTRAP_TOKEN, encoding="utf-8")
        if os.name == "nt":
            # Restrict ACL: SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544) Read-Only
            subprocess.run(
                ["icacls", str(_BOOTSTRAP_FILE), "/inheritance:r",
                 "/grant:r", "*S-1-5-18:(R)", "*S-1-5-32-544:(R)"],
                capture_output=True, timeout=5
            )
    except Exception as e:
        log.warning("Auth bootstrap initialization: %s", e)


AUTH_CODES: dict[str, float] = {}
SESSIONS: dict[str, float] = {}
CSRF_TOKENS: dict[str, str] = {}


@app.post("/api/auth/code")
def auth_code(request: Request):
    """Issues one-time launcher handshake code (valid for 30s).
    Requires administrative bootstrap token from ACL-restricted file."""
    auth_hdr = request.headers.get("Authorization", "")
    token = auth_hdr.replace("Bearer ", "").strip()
    is_bypass = os.environ.get("SC_DEV_AUTH_BYPASS") == "1"
    if not is_bypass and (not token or not secrets.compare_digest(token, _BOOTSTRAP_TOKEN)):
        raise HTTPException(403, "Forbidden: Invalid or missing administrative bootstrap token")
    code = uuid.uuid4().hex[:16]
    AUTH_CODES[code] = time.time() + 30
    return {"code": code}


class SessionReq(BaseModel):
    code: str


@app.post("/api/session")
def session_exchange(req: SessionReq):
    """Exchanges one-time code for HttpOnly session cookie + CSRF token."""
    now_t = time.time()
    exp = AUTH_CODES.pop(req.code, None)
    if not exp or now_t > exp:
        raise HTTPException(401, "Invalid or expired one-time code")
    sid = uuid.uuid4().hex
    csrf = uuid.uuid4().hex
    SESSIONS[sid] = now_t + 86400 * 7
    CSRF_TOKENS[sid] = csrf
    res = JSONResponse(content={"csrf": csrf, "status": "authenticated"})
    res.set_cookie("sc_session", sid, max_age=86400 * 7, httponly=True, samesite="strict")
    return res


@app.on_event("startup")
def _start():
    _init_bootstrap_token()
    threading.Thread(target=scheduler, daemon=True).start()
    threading.Thread(target=block_enforcer, daemon=True).start()
    threading.Thread(target=pause_watchdog, daemon=True).start()
    threading.Thread(target=hide_self_alerts, daemon=True).start()
    threading.Thread(target=init_ransomware_canaries, daemon=True).start()
    if os.name == "nt":
        threading.Thread(target=system_info, daemon=True).start()  # fills Defender status for the dashboard
    if psutil:
        psutil.cpu_percent(None)
    if get_setting("realtime", "0") == "1" and not is_paused():
        RT.start()
    log.info("Security Console %s started on %s:%s", VERSION, CFG["host"], CFG["port"])


@app.get("/api/status")
def status():
    s = CFG["services"]
    eng = {"clamav": svc_state(s["clamav"]), "freshclam": svc_state(s["freshclam"]),
           "osquery": "ready" if pathlib.Path(CFG["osqueryi"]).exists() else "missing",
           "sysmon": svc_state(s["sysmon"]),
           "yara": "ready" if pathlib.Path(CFG["yara"]).exists() else "missing",
           "sigma": "ready" if pathlib.Path(CFG["hayabusa"]).exists() else "missing"}
    return {"host": os.environ.get("COMPUTERNAME", "localhost"), "engines": eng, "realtime": RT.running,
            "version": VERSION, "blocked": len(blocked_rows()), "muted": len(mutes()), "pause": pause_state(), "time": now()}


@app.get("/api/stats")
def stats():
    with db() as con:
        sev = {r[0]: r[1] for r in con.execute("SELECT severity, COUNT(*) FROM events WHERE status='new' GROUP BY severity")}
        eng = {r[0]: r[1] for r in con.execute("SELECT engine, COUNT(*) FROM events WHERE engine!='console' GROUP BY engine")}
        day = [dict(r) for r in con.execute("SELECT substr(time,1,10) d, COUNT(*) n FROM events WHERE engine!='console' "
                                            "AND time >= date('now','-13 day') GROUP BY d ORDER BY d")]
    return {"severity": sev, "engine": eng, "daily": day}


@app.get("/api/events")
def events(limit: int = 200, engine: str | None = None, severity: str | None = None, q: str | None = None,
           status: str | None = None, origin: str | None = None, since_id: int | None = None,
           mitre: str | None = None):
    sql, args = "SELECT * FROM events WHERE 1=1", []
    for col, val in (("engine", engine), ("severity", severity), ("status", status), ("origin", origin)):
        if val:
            sql += f" AND {col}=?"
            args.append(val)
    if mitre:
        sql += " AND mitre_attack LIKE ?"
        args.append(f"%{mitre}%")
    if since_id is not None:
        sql += " AND id>?"
        args.append(since_id)
    if q:
        sql += " AND (rule LIKE ? OR target LIKE ? OR details LIKE ? OR mitre_attack LIKE ?)"
        args += [f"%{q}%"] * 4
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(min(limit, 2000))
    with db() as con:
        return [dict(r) for r in con.execute(sql, args)]


@app.get("/api/events/{eid}/explain")
def explain(eid: int):
    with db() as con:
        r = con.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not r:
        raise HTTPException(404)
    e = dict(r)
    return {"event": e, "explain": explain_event(e)}


@app.post("/api/events/{eid}/status")
def set_status(eid: int, req: StatusReq):
    if req.status not in ("new", "ack", "resolved"):
        raise HTTPException(400, "invalid status")
    with _db_lock, db() as con:
        con.execute("UPDATE events SET status=? WHERE id=?", (req.status, eid))
    return {"ok": True}


@app.post("/api/events/bulk")
def bulk_status(req: BulkReq):
    if req.status not in ("new", "ack", "resolved"):
        raise HTTPException(400, "invalid status")
    with _db_lock, db() as con:
        con.executemany("UPDATE events SET status=? WHERE id=?", [(req.status, i) for i in req.ids[:5000]])
    return {"ok": True, "count": len(req.ids)}


# ---- settings ---------------------------------------------------------------- #
def validate_setting(k, v):
    spec = SETTINGS_SCHEMA[k]
    kind = spec[0]
    if kind == "bool":
        return bool(v)
    if kind == "choice":
        for c in spec[1]:
            if str(c) == str(v):
                return c
        raise HTTPException(400, f"Invalid value for {k}")
    if kind == "int":
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise HTTPException(400, f"{k} must be a number")
        return max(spec[1], min(spec[2], v))
    if kind == "time":
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(v)):
            raise HTTPException(400, "Time must look like 14:30")
        return str(v)
    if kind == "folders":
        out = []
        for p in v or []:
            p = os.path.normpath(os.path.expandvars(str(p).strip().strip('"')))
            if not os.path.isdir(p):
                raise HTTPException(404, f"Folder not found: {p}")
            out.append(p)
        return list(dict.fromkeys(out))
    raise HTTPException(400, k)


@app.get("/api/settings")
def get_settings():
    return {k: CFG.get(k, DEFAULT_CFG.get(k)) for k in SETTINGS_SCHEMA} | {
        "_defaults": {k: DEFAULT_CFG.get(k) for k in SETTINGS_SCHEMA}}


@app.post("/api/settings")
def save_settings(body: dict):
    changes = {k: validate_setting(k, v) for k, v in body.items() if k in SETTINGS_SCHEMA}
    stored = json.loads(get_setting("config", "{}") or "{}")
    stored.update(changes)
    set_setting("config", json.dumps(stored))
    old_folders = CFG.get("rt_extra_folders")
    CFG.update(changes)
    if "rt_extra_folders" in changes and changes["rt_extra_folders"] != old_folders:
        RT.restart()
    if changes.get("hide_self"):
        hide_self_alerts()
    log.info("settings changed: %s", changes)
    return get_settings()


@app.post("/api/settings/reset")
def reset_settings():
    set_setting("config", "{}")
    CFG.update({k: DEFAULT_CFG[k] for k in SETTINGS_SCHEMA})
    RT.restart()
    return get_settings()


# ---- real-time ---------------------------------------------------------------- #
@app.get("/api/realtime")
def realtime_status():
    st = RT.status()
    st["pause"] = pause_state()
    with db() as con:
        st["last_event_id"] = con.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
        st["open"] = con.execute("SELECT COUNT(*) FROM events WHERE status='new'").fetchone()[0]
        st["today"] = con.execute("SELECT COUNT(*) FROM events WHERE origin='realtime' AND engine!='console' "
                                  "AND time>=date('now','localtime')").fetchone()[0]
    return st


@app.post("/api/realtime")
def realtime_set(req: RealtimeReq):
    if req.enabled and is_paused():
        raise HTTPException(409, "Protection is paused. Resume it first (power button at the top).")
    set_setting("realtime", "1" if req.enabled else "0")
    RT.start() if req.enabled else RT.stop()
    return realtime_status()


# ---- programs ----------------------------------------------------------------- #
@app.get("/api/processes")
def processes(path: str):
    return {"running": find_processes(path), "protected": protected_reason(path)}


@app.post("/api/processes/stop")
def stop_process(req: StopReq):
    try:
        res = stop_pid(req.pid) if req.pid else stop_path(req.path or "")
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    if res.get("stopped"):
        emit("console", "low", "Program stopped", res.get("path") or req.path or str(req.pid),
             details="Stopped from Security Console.")
    return res


@app.get("/api/blocked")
def blocked_list():
    rows = blocked_rows()
    for r in rows:
        r["exists"] = os.path.exists(r["path"])
    return rows


@app.post("/api/blocked")
def block_program(req: BlockReq):
    path = os.path.normpath(req.path.strip().strip('"'))
    why = protected_reason(path)
    if why:
        raise HTTPException(400, why)
    if not os.path.isfile(path):
        raise HTTPException(404, "Program file not found")
    if req.firewall:
        try:
            firewall_block(path, True)
        except RuntimeError as e:
            raise HTTPException(400, str(e))
    with _db_lock, db() as con:
        con.execute("INSERT INTO blocked(path,name,sha256,firewall,run_block,note,created) VALUES(?,?,?,?,?,?,?) "
                    "ON CONFLICT(path) DO UPDATE SET firewall=MAX(firewall,excluded.firewall), "
                    "run_block=MAX(run_block,excluded.run_block)",
                    (path, os.path.basename(path), sha256(path), int(req.firewall), int(req.run_block), req.note, now()))
    _BLOCK["rows"] = None
    stopped = stop_path(path, quiet=True)["stopped"] if req.stop_now and req.run_block else 0
    what = " and ".join(x for x in ("can't run" if req.run_block else "", "can't use the internet" if req.firewall else "") if x)
    emit("console", "low", "Program blocked", path, details=f"'{os.path.basename(path)}' {what}.")
    return {"ok": True, "stopped": stopped}


@app.post("/api/firewall")
def firewall(req: FirewallReq):
    path = os.path.normpath(req.path)
    if req.block:
        return block_program(BlockReq(path=path, firewall=True, run_block=False, stop_now=False))
    try:
        firewall_block(path, False)
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    with _db_lock, db() as con:
        con.execute("UPDATE blocked SET firewall=0 WHERE path=?", (path,))
        con.execute("DELETE FROM blocked WHERE path=? AND firewall=0 AND run_block=0", (path,))
    _BLOCK["rows"] = None
    return {"ok": True}


@app.delete("/api/blocked/{bid}")
def unblock(bid: int):
    with db() as con:
        r = con.execute("SELECT * FROM blocked WHERE id=?", (bid,)).fetchone()
    if not r:
        raise HTTPException(404)
    if r["firewall"]:
        try:
            firewall_block(r["path"], False)
        except RuntimeError:
            pass
    with _db_lock, db() as con:
        con.execute("DELETE FROM blocked WHERE id=?", (bid,))
    _BLOCK["rows"] = None
    emit("console", "low", "Program unblocked", r["path"])
    return {"ok": True}


# ---- muted alerts -------------------------------------------------------------- #
# ---- power: pause / resume / exit ---------------------------------------------- #
class PauseReq(BaseModel):
    minutes: int | None = None   # None/0 = until resumed


@app.get("/api/power")
def power_state():
    return pause_state()


@app.post("/api/power/pause")
def power_pause(req: PauseReq):
    if req.minutes and not (1 <= req.minutes <= 1440):
        raise HTTPException(400, "Pause for 1 to 1440 minutes")
    return pause_all(req.minutes)


@app.post("/api/power/resume")
def power_resume():
    return resume_all()


@app.post("/api/power/exit")
def power_exit():
    exit_app()
    return {"ok": True}


# ---- system information --------------------------------------------------------- #
@app.get("/api/system/info")
def sys_info(refresh: bool = False):
    return system_info(refresh)


@app.get("/api/overview")
def api_overview():
    return overview()


@app.get("/api/network")
def api_network():
    try:
        return network_connections()
    except RuntimeError as e:
        raise HTTPException(500, str(e))


class StartupReq(BaseModel):
    name: str
    source: str = ""
    path: str = ""
    enable: bool


@app.post("/api/startup")
def api_startup(req: StartupReq):
    try:
        set_startup(req.name, req.source, req.path, req.enable)
    except (RuntimeError, OSError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "enabled": req.enable}


@app.get("/api/system/live")
def sys_live(lite: bool = False):
    try:
        return system_live(lite)
    except RuntimeError as e:
        raise HTTPException(500, str(e))


@app.get("/api/mutes")
def mutes_list():
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM mutes ORDER BY id DESC")]


@app.post("/api/mutes")
def add_mute(req: MuteReq):
    if not req.rule.strip():
        raise HTTPException(400, "rule is required")
    with _db_lock, db() as con:
        con.execute("INSERT OR IGNORE INTO mutes(engine,rule,match,note,created) VALUES(?,?,?,?,?)",
                    (req.engine, req.rule, req.match.strip(), req.note, now()))
        # also tidy up existing alerts that match
        args = [req.rule] + ([req.engine] if req.engine else [])
        rows = con.execute("SELECT id,target,details FROM events WHERE status='new' AND rule=?"
                           + (" AND engine=?" if req.engine else ""), args).fetchall()
        ids = [r["id"] for r in rows if not req.match or req.match.lower() in f'{r["target"]} {r["details"]}'.lower()]
        con.executemany("UPDATE events SET status='ack' WHERE id=?", [(i,) for i in ids])
    _MUTES["rows"] = None
    return {"ok": True, "hidden": len(ids)}


@app.delete("/api/mutes/{mid}")
def del_mute(mid: int):
    with _db_lock, db() as con:
        con.execute("DELETE FROM mutes WHERE id=?", (mid,))
    _MUTES["rows"] = None
    return {"ok": True}


# ---- maintenance ---------------------------------------------------------------- #
@app.post("/api/maintenance/{action}")
def maintenance(action: str):
    jobs_map = {
        "update_signatures": ("maintenance", "Update virus definitions", update_signatures),
        "update_rules": ("maintenance", "Update behavior rules", update_rules),
        "cleanup": ("maintenance", "Clean up old history", lambda: cleanup_history()),
    }
    if action == "selftest":
        return {"job": start_job("scan", "Protection self-test", lambda jid: self_test(jid), pass_id=True)}
    if action not in jobs_map:
        raise HTTPException(404)
    kind, label, fn = jobs_map[action]
    return {"job": start_job(kind, label, fn)}


# ---- scanning ------------------------------------------------------------------- #
@app.post("/api/scan")
def scan(req: ScanReq):
    targets = req.targets or ([req.path] if req.path else [])
    if not targets:
        raise HTTPException(400, "Choose something to scan")
    if req.action not in ("report", "quarantine"):
        raise HTTPException(400, "action must be report or quarantine")
    action = "report" if req.mode == "check" else req.action
    for t in targets:
        if not t.startswith("@") and not os.path.exists(os.path.expandvars(t.strip().strip('"'))):
            raise HTTPException(404, f"Not found: {t}")
    label = req.label or {"@quick": "Quick scan", "@full": "Full scan"}.get(targets[0], ", ".join(targets))
    return {"job": start_scan(targets, action, req.mode, label)}


@app.post("/api/jobs/{jid}/cancel")
def cancel(jid: str):
    JOB_CANCEL.add(jid)
    return {"ok": True}


@app.get("/api/places")
def places():
    return {"drives": drives(), "quick": quick_targets(), "users": [{"name": u.name, "path": str(u)} for u in user_profiles()]}


@app.get("/api/browse")
def browse(path: str = "", files: bool = False):
    if not path:
        return {"path": "", "parent": None, "drives": drives(), "dirs": [], "files": []}
    p = os.path.normpath(os.path.expandvars(path))
    if not os.path.isdir(p):
        raise HTTPException(404, f"Folder not found: {path}")
    ex = Exclusions()
    dirs, fl = [], []
    try:
        with os.scandir(p) as it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False) and not e.is_symlink():
                        dirs.append({"name": e.name, "path": e.path, "excluded": ex.path(e.path)})
                    elif files and e.is_file(follow_symlinks=False):
                        fl.append({"name": e.name, "path": e.path, "size": e.stat().st_size, "excluded": ex.file(e.path)})
                except OSError:
                    pass
    except PermissionError:
        raise HTTPException(403, "Windows won't let us open this folder")
    parent = os.path.dirname(p)
    key = lambda x: x["name"].lower()
    return {"path": p, "parent": "" if parent == p else parent, "excluded": ex.path(p),
            "dirs": sorted(dirs, key=key), "files": sorted(fl, key=key)[:1000]}


@app.get("/api/exclusions")
def exclusions():
    return {"builtin": builtin_exclusions(), "items": list_exclusions()}


@app.post("/api/exclusions")
def add_exclusion(req: ExclusionReq):
    v = req.value.strip().strip('"')
    if req.kind == "ext":
        v = "." + v.lower().lstrip("*.").strip()
        if len(v) < 2 or any(c in v for c in "\\/:*?"):
            raise HTTPException(400, "Enter a file type like .iso or .vhdx")
    elif req.kind == "path":
        v = os.path.normpath(os.path.expandvars(v))
        if len(v) <= 3 and os.name == "nt":
            raise HTTPException(400, "Excluding a whole drive isn't allowed. Pick a folder instead.")
        if not os.path.exists(v):
            raise HTTPException(404, f"Not found: {v}")
    else:
        raise HTTPException(400, "kind must be path or ext")
    with _db_lock, db() as con:
        con.execute("INSERT OR IGNORE INTO exclusions(kind,value,note,created) VALUES(?,?,?,?)", (req.kind, v, req.note, now()))
    RT._ex = None
    return {"ok": True, "value": v}


@app.delete("/api/exclusions/{xid}")
def del_exclusion(xid: int):
    with _db_lock, db() as con:
        con.execute("DELETE FROM exclusions WHERE id=?", (xid,))
    RT._ex = None
    return {"ok": True}


@app.get("/api/jobs")
def jobs(limit: int = 40):
    with db() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM jobs ORDER BY started DESC LIMIT ?", (limit,))]
    for r in rows:
        r["result"] = json.loads(r["result"]) if r["result"] else None
        r["progress"] = json.loads(r["progress"]) if r.get("progress") else None
    return rows


@app.get("/api/jobs/{jid}")
def job(jid: str):
    with db() as con:
        r = con.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    if not r:
        raise HTTPException(404)
    r = dict(r)
    r["result"] = json.loads(r["result"]) if r["result"] else None
    r["progress"] = json.loads(r["progress"]) if r.get("progress") else None
    return r


@app.get("/api/hunts")
def hunts():
    return [{"id": k, "title": v["title"], "sql": v["sql"]} for k, v in HUNTS.items()]


@app.post("/api/hunts/{name}")
def hunt(name: str):
    if name not in HUNTS:
        raise HTTPException(404)
    try:
        return run_hunt(name, record=False)
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/query")
def query(req: QueryReq):
    sql = req.sql.strip()
    if not sql.lower().startswith(("select", "with")):
        raise HTTPException(400, "Only SELECT queries are allowed")
    try:
        return osquery(sql)
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/sigma/run")
def sigma_now():
    return {"job": start_job("sigma", "Windows event logs", lambda: {"new_events": run_sigma()})}


@app.post("/api/quarantine")
def quarantine(req: PathReq):
    try:
        return {"ok": True, "stored": quarantine_file(req.path)}
    except FileNotFoundError:
        raise HTTPException(404, "File not found")
    except OSError as e:
        raise HTTPException(400, f"Couldn't move the file: {e}")


@app.get("/api/quarantine")
def quarantine_list():
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM quarantine ORDER BY id DESC")]


@app.post("/api/quarantine/{qid}/restore")
def restore(qid: int):
    with db() as con:
        r = con.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
    if not r:
        raise HTTPException(404)
    shutil.move(r["stored"], r["original"])
    with _db_lock, db() as con:
        con.execute("DELETE FROM quarantine WHERE id=?", (qid,))
    emit("console", "low", "File restored", r["original"])
    return {"ok": True}


@app.delete("/api/quarantine/{qid}")
def delete_quarantined(qid: int):
    with db() as con:
        r = con.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
    if not r:
        raise HTTPException(404)
    try:
        os.remove(r["stored"])
    except FileNotFoundError:
        pass
    with _db_lock, db() as con:
        con.execute("DELETE FROM quarantine WHERE id=?", (qid,))
    emit("console", "low", "Quarantined file deleted", r["original"])
    return {"ok": True}


# --------------------------------------------------------------------------- #
# UI
# --------------------------------------------------------------------------- #
UI_DIR = BASE / "ui"
if not UI_DIR.exists():
    UI_DIR = pathlib.Path(__file__).resolve().parent.parent / "ui"
if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")

    @app.get("/")
    def index():
        return FileResponse(UI_DIR / "index.html", headers={"Cache-Control": "no-store"})


if __name__ == "__main__":
    uvicorn.run(app, host=CFG["host"], port=int(CFG["port"]), log_level="info")
