"""
OmniShield add-on 1.9 - VirusTotal
  * Look up files (by fingerprint), folders, links, websites/IPs and hashes on VirusTotal
  * "Is this safe?" asks VirusTotal first, then runs the local antivirus + pattern rules
  * Strict quota guard: never goes over your per-minute, daily or monthly limits
    (free key: 4 / minute, 500 / day, 15,500 / month). Every call is reserved before it
    is sent, saved results are re-used, and real usage is synced from VirusTotal for free.
Privacy: files are only ever identified by their SHA-256 fingerprint unless you allow uploads.
Links, websites and IP addresses you check are sent to VirusTotal.
"""
import base64
import datetime as dt
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

M = None
BASE_URL = os.environ.get("SC_VT_BASE", "https://www.virustotal.com/api/v3")
WINDOW = float(os.environ.get("SC_VT_WINDOW", "60"))      # seconds in the per-minute window (tests shorten it)
PAD = 1.0 if WINDOW >= 60 else 0.2                         # small safety gap so clocks never disagree
GUI = "https://www.virustotal.com/gui"
MAX_UPLOAD = 32 * 1024 * 1024
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
RISKY = {".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx", ".msi", ".msp", ".msix", ".appx", ".bat", ".cmd",
         ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".py", ".reg", ".inf", ".chm",
         ".iso", ".img", ".vhd", ".vhdx", ".zip", ".rar", ".7z", ".cab", ".gz", ".tar", ".doc", ".docm", ".docx", ".dot",
         ".dotm", ".xls", ".xlsm", ".xlsx", ".xlsb", ".xlam", ".ppt", ".pptm", ".pptx", ".rtf", ".pdf", ".one", ".html",
         ".htm", ".svg", ".apk", ".dmg", ".elf", ".bin"}
DEFAULTS = {"plan": "free", "per_min": 4, "per_day": 500, "per_month": 15500, "reserve": 25, "use_in_check": True,
            "check_max": 20, "upload": "never", "cache_days": 7, "only_risky": True, "folder_max": 100}
PLANS = {"free": (4, 500, 15500)}


class QuotaError(Exception):
    def __init__(self, msg, wait=0.0, which=""):
        super().__init__(msg)
        self.wait, self.which = wait, which


class VTError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Settings and API key (encrypted with Windows DPAPI when available)
# --------------------------------------------------------------------------- #
def _get(k, default=""):
    return M.get_setting("vt_" + k, default)


def _set(k, v):
    M.set_setting("vt_" + k, v)


def cfg() -> dict:
    try:
        c = {**DEFAULTS, **json.loads(_get("cfg", "{}") or "{}")}
    except ValueError:
        c = dict(DEFAULTS)
    if c["plan"] in PLANS:
        c["per_min"], c["per_day"], c["per_month"] = PLANS[c["plan"]]
    return c


def _protect(s: str) -> str:
    try:
        import win32crypt  # type: ignore
        blob = win32crypt.CryptProtectData(s.encode(), "SecurityConsole VT", None, None, None, 0x4)
        return "dpapi:" + base64.b64encode(blob).decode()
    except Exception:
        return "plain:" + base64.b64encode(s.encode()).decode()


def _unprotect(s: str) -> str:
    if not s:
        return ""
    kind, _, data = s.partition(":")
    try:
        raw = base64.b64decode(data)
        if kind == "dpapi":
            import win32crypt  # type: ignore
            return win32crypt.CryptUnprotectData(raw, None, None, None, 0)[1].decode()
        return raw.decode()
    except Exception:
        M.log.exception("VirusTotal key couldn't be read")
        return ""


def api_key() -> str:
    return _unprotect(_get("key"))


def mask(k: str) -> str:
    return ("•" * 8 + k[-4:]) if k else ""


# --------------------------------------------------------------------------- #
# Quota guard
# --------------------------------------------------------------------------- #
_Q = threading.Lock()


def _utc_now():
    return dt.datetime.now(dt.timezone.utc)


def _day_start():
    n = _utc_now()
    return n.replace(hour=0, minute=0, second=0, microsecond=0)


def _month_start():
    return _day_start().replace(day=1)


def _next_day():
    return _day_start() + dt.timedelta(days=1)


def _next_month():
    m = _month_start()
    return (m.replace(year=m.year + 1, month=1) if m.month == 12 else m.replace(month=m.month + 1))


def _count(since: float) -> int:
    with M.db() as con:
        return con.execute("SELECT COUNT(*) FROM addon_vt_calls WHERE ts>=?", (since,)).fetchone()[0]


def usage() -> dict:
    c = cfg()
    now = time.time()
    d0, m0 = _day_start().timestamp(), _month_start().timestamp()
    local_min = _count(now - WINDOW - PAD)
    local_day, local_month = _count(d0), _count(m0)
    # combine with what VirusTotal itself reported (covers the key being used elsewhere too)
    try:
        r = json.loads(_get("remote", "{}") or "{}")
    except ValueError:
        r = {}
    day, month = local_day, local_month
    if r.get("ts"):
        since = _count(r["ts"])
        if r["ts"] >= d0 and r.get("day_used") is not None:
            day = max(day, r["day_used"] + since)
        if r["ts"] >= m0 and r.get("month_used") is not None:
            month = max(month, r["month_used"] + since)
    lim_day = min(c["per_day"], r.get("day_allowed") or c["per_day"]) if r.get("day_allowed") else c["per_day"]
    lim_month = min(c["per_month"], r.get("month_allowed") or c["per_month"]) if r.get("month_allowed") else c["per_month"]
    blocked = float(_get("blocked_until", "0") or 0)
    oldest = None
    if local_min >= c["per_min"]:
        with M.db() as con:
            row = con.execute("SELECT ts FROM addon_vt_calls WHERE ts>=? ORDER BY ts LIMIT 1 OFFSET ?",
                              (now - WINDOW - PAD, local_min - c["per_min"])).fetchone()
        oldest = row[0] if row else None
    wait = max(0.0, (oldest + WINDOW + PAD - now) if oldest else 0.0, blocked - now)
    return {"minute": {"used": min(local_min, c["per_min"]), "limit": c["per_min"], "left": max(0, c["per_min"] - local_min)},
            "day": {"used": day, "limit": lim_day, "left": max(0, lim_day - day), "resets": _next_day().isoformat()},
            "month": {"used": month, "limit": lim_month, "left": max(0, lim_month - month), "resets": _next_month().isoformat()},
            "wait": round(wait, 1), "reserve": c["reserve"],
            "synced": r.get("ts"), "detected": {"day": r.get("day_allowed"), "month": r.get("month_allowed")},
            "blocked_until": blocked if blocked > now else None}


def reserve_call(kind: str, target: str, batch: bool = False, wait: bool = False, cancelled=None) -> int:
    """Book one request slot BEFORE talking to VirusTotal. Raises QuotaError instead of going over a limit."""
    while True:
        with _Q:
            u = usage()
            if u["day"]["left"] <= 0:
                raise QuotaError(f"You've used all {u['day']['limit']} VirusTotal lookups for today. "
                                 f"More are available at {_local(u['day']['resets'])}.", which="day")
            if u["month"]["left"] <= 0:
                raise QuotaError(f"You've used all {u['month']['limit']:,} VirusTotal lookups for this month. "
                                 f"More are available on {_local(u['month']['resets'], True)}.", which="month")
            if batch and u["day"]["left"] <= u["reserve"]:
                raise QuotaError(f"Stopped to keep {u['reserve']} lookups in reserve for your own checks today "
                                 f"(change this in Settings > VirusTotal).", which="reserve")
            if u["wait"] <= 0:
                with M._db_lock, M.db() as con:
                    cur = con.execute("INSERT INTO addon_vt_calls(ts,kind,target,status) VALUES(?,?,?,0)",
                                      (time.time(), kind, target[:300]))
                    return cur.lastrowid
            w = u["wait"]
        if not wait:
            raise QuotaError(f"VirusTotal allows {cfg()['per_min']} lookups per minute. Next one in {int(w + .99)} s.",
                         wait=w, which="minute")
        end = time.time() + w
        while time.time() < end:
            if cancelled and cancelled():
                raise QuotaError("Stopped.", which="cancel")
            time.sleep(min(0.5, end - time.time() + 0.01))


def _local(iso: str, date_only=False) -> str:
    t = dt.datetime.fromisoformat(iso).astimezone()
    return t.strftime("%d %b") if date_only else t.strftime("%I:%M %p").lstrip("0")


def _finish_call(cid: int, status: int):
    with M._db_lock, M.db() as con:
        con.execute("UPDATE addon_vt_calls SET status=? WHERE id=?", (status, cid))


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def _http(method: str, path: str, key: str, data: bytes | None = None, ctype: str | None = None, timeout=60):
    req = urllib.request.Request(BASE_URL + path, data=data, method=method)
    req.add_header("x-apikey", key)
    req.add_header("accept", "application/json")
    req.add_header("user-agent", "SecurityConsole/1.9")
    if ctype:
        req.add_header("content-type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except ValueError:
            body = {}
        return e.code, body
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise VTError(f"Can't reach VirusTotal - check the internet connection or firewall ({getattr(e, 'reason', e)}).")


def call(method: str, path: str, kind: str, target: str, data=None, ctype=None, batch=False, wait=False, cancelled=None):
    """One counted request: reserve a slot, send, handle quota answers from VirusTotal."""
    key = api_key()
    if not key:
        raise VTError("Add your VirusTotal API key in Settings > VirusTotal first.")
    cid = reserve_call(kind, target, batch=batch, wait=wait, cancelled=cancelled)
    status, body = _http(method, path, key, data, ctype)
    _finish_call(cid, status)
    err = (body.get("error") or {}) if isinstance(body, dict) else {}
    if status == 429:
        code = err.get("code", "")
        if code == "QuotaExceededError":
            _set("blocked_until", str(_next_day().timestamp()))
            threading.Thread(target=sync_quiet, daemon=True).start()
            raise QuotaError("VirusTotal says this key's quota is used up. OmniShield will wait until it resets.", which="day")
        _set("blocked_until", str(time.time() + WINDOW))
        raise QuotaError("VirusTotal asked us to slow down. Trying again in a minute.", wait=WINDOW, which="minute")
    if status == 401:
        raise VTError("VirusTotal didn't accept the API key. Check it in Settings > VirusTotal.")
    if status == 403:
        raise VTError(err.get("message") or "VirusTotal didn't allow this request with your key.")
    return status, body


def sync_quiet():
    try:
        sync_remote()
    except Exception as e:
        M.log.info("VirusTotal usage sync skipped: %s", e)


def sync_remote() -> dict:
    """Read real usage from VirusTotal. This endpoint doesn't use any quota."""
    key = api_key()
    if not key:
        return {}
    status, body = _http("GET", f"/users/{urllib.parse.quote(key)}/overall_quotas", key, timeout=30)
    if status != 200:
        return {"ok": False, "status": status, "error": ((body or {}).get("error") or {}).get("message", "")}
    d = body.get("data", {}) or {}

    def pick(name):
        node = d.get(name) or {}
        node = node.get("user", node) if isinstance(node, dict) else {}
        return node.get("used"), node.get("allowed")

    du, da = pick("api_requests_daily")
    mu, ma = pick("api_requests_monthly")
    r = {"ts": time.time(), "day_used": du, "day_allowed": da, "month_used": mu, "month_allowed": ma}
    _set("remote", json.dumps(r))
    if da and du is not None and du < da and float(_get("blocked_until", "0") or 0) > time.time():
        _set("blocked_until", "0")
    return {"ok": True, **r}


# --------------------------------------------------------------------------- #
# Lookups, summaries and the results cache
# --------------------------------------------------------------------------- #
def url_id(u: str) -> str:
    return base64.urlsafe_b64encode(u.encode()).decode().rstrip("=")


def gui_link(kind: str, key: str) -> str:
    return {"file": f"{GUI}/file/{key}", "url": f"{GUI}/url/{url_id(key)}", "domain": f"{GUI}/domain/{key}",
            "ip": f"{GUI}/ip-address/{key}"}.get(kind, GUI)


def verdict_of(stats: dict) -> str:
    mal, sus = int(stats.get("malicious") or 0), int(stats.get("suspicious") or 0)
    if mal >= 3:
        return "dangerous"
    if mal or sus >= 2:
        return "suspicious"
    if sum(int(v or 0) for v in stats.values()) == 0:
        return "unknown"
    return "clean"


def summarize(kind: str, key: str, attrs: dict, analysis: bool = False) -> dict:
    stats = attrs.get("stats" if analysis else "last_analysis_stats") or {}
    results = attrs.get("results" if analysis else "last_analysis_results") or {}
    total = sum(int(stats.get(k) or 0) for k in ("malicious", "suspicious", "undetected", "harmless"))
    det = [{"engine": e, "result": r.get("result") or r.get("category"), "category": r.get("category")}
           for e, r in results.items() if r.get("category") in ("malicious", "suspicious")]
    det.sort(key=lambda x: (x["category"] != "malicious", x["engine"].lower()))
    ts = lambda v: dt.datetime.fromtimestamp(v).isoformat(timespec="seconds") if isinstance(v, (int, float)) and v else None
    s = {"kind": kind, "key": key, "found": True, "verdict": verdict_of(stats), "stats": stats, "engines": total,
         "malicious": int(stats.get("malicious") or 0), "suspicious": int(stats.get("suspicious") or 0),
         "detections": det[:40], "link": gui_link(kind, key), "fetched": dt.datetime.now().isoformat(timespec="seconds"),
         "last_analysis": ts(attrs.get("last_analysis_date") or attrs.get("date")), "reputation": attrs.get("reputation"),
         "tags": (attrs.get("tags") or [])[:12]}
    if kind == "file":
        ptc = attrs.get("popular_threat_classification") or {}
        s.update(name=attrs.get("meaningful_name") or (attrs.get("names") or [None])[0], names=(attrs.get("names") or [])[:8],
                 type=attrs.get("type_description"), size=attrs.get("size"), threat=ptc.get("suggested_threat_label"),
                 first_seen=ts(attrs.get("first_submission_date")), times_submitted=attrs.get("times_submitted"),
                 signed=((attrs.get("signature_info") or {}).get("verified")), md5=attrs.get("md5"), sha1=attrs.get("sha1"),
                 sha256=attrs.get("sha256") or key)
    elif kind == "url":
        s.update(title=attrs.get("title"), final_url=attrs.get("last_final_url"), categories=list((attrs.get("categories") or {}).values())[:6],
                 first_seen=ts(attrs.get("first_submission_date")))
    elif kind in ("domain", "ip"):
        s.update(categories=list((attrs.get("categories") or {}).values())[:6], country=attrs.get("country"),
                 owner=attrs.get("as_owner") or attrs.get("registrar"), created=ts(attrs.get("creation_date")))
    s["what"] = explain(s)
    return s


def not_found(kind: str, key: str) -> dict:
    return {"kind": kind, "key": key, "found": False, "verdict": "unknown", "link": gui_link(kind, key),
            "fetched": dt.datetime.now().isoformat(timespec="seconds"),
            "what": {"file": "VirusTotal has never seen this file. That isn't good or bad on its own - new or rare files are often unknown.",
                     "url": "VirusTotal hasn't checked this link yet.",
                     "domain": "VirusTotal has no information about this website.",
                     "ip": "VirusTotal has no information about this address."}.get(kind, "Not found on VirusTotal.")}


def explain(s: dict) -> str:
    n, t, sus = s.get("malicious", 0), s.get("engines", 0), s.get("suspicious", 0)
    thing = {"file": "this file", "url": "this link", "domain": "this website", "ip": "this address"}.get(s["kind"], "it")
    if s["verdict"] == "dangerous":
        x = f"{n} of {t} security companies say {thing} is malicious."
        if s.get("threat"):
            x += f" Most call it '{s['threat']}'."
        return x + (" Don't open it." if s["kind"] == "file" else " Don't visit it or enter any details there.")
    if s["verdict"] == "suspicious":
        return (f"{n} of {t} security companies flag {thing}" if n else f"{sus} of {t} security companies think {thing} is suspicious") + \
               ". A few detections are sometimes false alarms - be careful, and use 'Is this safe?' to check locally too."
    if s["verdict"] == "clean":
        return f"None of the {t} security companies on VirusTotal flag {thing}."
    return f"VirusTotal knows {thing}, but no security company has analysed it yet."


def cache_get(kind: str, key: str):
    c = cfg()
    with M.db() as con:
        r = con.execute("SELECT data, fetched FROM addon_vt_cache WHERE kind=? AND key=?", (kind, key)).fetchone()
    if not r:
        return None
    d = json.loads(r[0])
    max_age = (1 if not d.get("found") else c["cache_days"]) * 86400
    if time.time() - r[1] > max_age:
        return None
    d["cached"] = True
    return d


def cache_put(d: dict, label: str = ""):
    d = {k: v for k, v in d.items() if k != "cached"}
    with M._db_lock, M.db() as con:
        con.execute("INSERT INTO addon_vt_cache(kind,key,label,verdict,data,fetched) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(kind,key) DO UPDATE SET label=COALESCE(NULLIF(excluded.label,''),addon_vt_cache.label),"
                    "verdict=excluded.verdict,data=excluded.data,fetched=excluded.fetched",
                    (d["kind"], d["key"], label, d["verdict"], json.dumps(d), time.time()))


def norm_input(kind: str, value: str) -> str:
    v = (value or "").strip().strip('"')
    if kind == "hash":
        v = v.lower()
        if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", v):
            raise VTError("That doesn't look like an MD5, SHA-1 or SHA-256 fingerprint.")
    elif kind == "url":
        if not re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
            v = "http://" + v
        p = urllib.parse.urlsplit(v)
        if not p.netloc:
            raise VTError("That doesn't look like a web link.")
    elif kind == "domain":
        v = re.sub(r"^[a-z]+://", "", v.lower()).split("/")[0].split(":")[0]
        if not re.fullmatch(r"[a-z0-9.-]+\.[a-z0-9-]{2,}", v):
            raise VTError("That doesn't look like a website name, e.g. example.com.")
    elif kind == "ip":
        import ipaddress
        try:
            v = str(ipaddress.ip_address(v))
        except ValueError:
            raise VTError("That doesn't look like an IP address.")
    return v


def lookup(kind: str, value: str, force=False, batch=False, wait=False, cancelled=None, label="") -> dict:
    if kind == "hash":
        kind = "file"
    key = value
    if not force:
        c = cache_get(kind, key)
        if c:
            return c
    path = {"file": f"/files/{key}", "url": f"/urls/{url_id(key)}", "domain": f"/domains/{key}",
            "ip": f"/ip_addresses/{urllib.parse.quote(key)}"}[kind]
    status, body = call("GET", path, kind, key, batch=batch, wait=wait, cancelled=cancelled)
    if status == 404:
        d = not_found(kind, key)
    elif status == 200:
        d = summarize(kind, key, ((body.get("data") or {}).get("attributes") or {}))
    else:
        raise VTError(((body or {}).get("error") or {}).get("message") or f"VirusTotal answered with error {status}.")
    cache_put(d, label)
    d["cached"] = False
    return d


def poll_analysis(aid: str, kind: str, key: str, cancelled=None, tries=4, every=20) -> dict | None:
    for i in range(tries):
        end = time.time() + (every if i else every / 2)
        while time.time() < end:
            if cancelled and cancelled():
                return None
            time.sleep(0.5)
        status, body = call("GET", f"/analyses/{aid}", "analysis", key, wait=True, cancelled=cancelled)
        a = ((body.get("data") or {}).get("attributes") or {})
        if a.get("status") == "completed":
            d = summarize(kind, key, a, analysis=True)
            cache_put(d)
            return d
    return None


# --------------------------------------------------------------------------- #
# Folder checks and "Is this safe?"
# --------------------------------------------------------------------------- #
def gather(root: str, only_risky: bool, limit=20000):
    files, skipped = [], 0
    if os.path.isfile(root):
        return [root], 0
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if not os.path.islink(os.path.join(d, x))]
        for f in fs:
            p = os.path.join(d, f)
            if only_risky and os.path.splitext(f)[1].lower() not in RISKY:
                skipped += 1
                continue
            files.append(p)
            if len(files) >= limit:
                return files, skipped
    return files, skipped


def plan(path: str, only_risky=True, max_files=None) -> dict:
    p = os.path.normpath(os.path.expandvars(path.strip().strip('"')))
    if not os.path.exists(p):
        raise VTError(f"Not found: {p}")
    c, u = cfg(), usage()
    files, skipped = gather(p, only_risky)
    max_files = int(max_files or c["folder_max"])
    budget = max(0, min(u["day"]["left"] - u["reserve"], u["month"]["left"]))
    need = min(len(files), max_files)
    return {"path": p, "files": len(files), "skipped_types": skipped, "max_files": max_files,
            "lookups_max": min(need, budget), "budget": budget, "per_min": c["per_min"],
            "minutes": round(min(need, budget) / max(1, c["per_min"]), 1), "usage": u}


def vt_files(jid, files: list[str], max_files: int, cancelled, progress, emit_events=True) -> dict:
    """Look up many files by fingerprint, cheapest first (saved results cost nothing)."""
    res = {"checked": 0, "cached": 0, "lookups": 0, "flagged": [], "unknown": 0, "clean": 0, "errors": [],
           "skipped_limit": 0, "items": [], "stopped": ""}
    by_hash: dict[str, list[str]] = {}
    for i, f in enumerate(files):
        if cancelled():
            res["stopped"] = "cancel"
            return res
        try:
            if os.path.getsize(f) == 0:
                continue
        except OSError:
            continue
        h = M.sha256(f)
        if h:
            by_hash.setdefault(h, []).append(f)
        if i % 25 == 0:
            progress(phase="vt_hash", vt_done=i, vt_total=len(files))
    hashes = list(by_hash)
    cached = [h for h in hashes if cache_get("file", h)]
    todo = [h for h in hashes if h not in set(cached)]
    order = cached + todo[:max(0, max_files - len(cached)) if max_files else len(todo)]
    res["skipped_limit"] = max(0, len(hashes) - len(order))
    for n, h in enumerate(order):
        if cancelled():
            res["stopped"] = "cancel"
            break
        progress(phase="virustotal", vt_done=n, vt_total=len(order), current=by_hash[h][0], vt_cached=len(cached),
                 wait=usage()["wait"] if h not in cached else 0)
        try:
            d = lookup("file", h, batch=True, wait=True, cancelled=cancelled, label=os.path.basename(by_hash[h][0]))
        except QuotaError as e:
            if e.which != "cancel":
                res["stopped"] = str(e)
                res["skipped_limit"] += len(order) - n
            break
        except VTError as e:
            res["errors"].append(str(e))
            res["stopped"] = str(e)
            break
        res["checked"] += 1
        res["cached" if d.get("cached") else "lookups"] += 1
        if d["verdict"] in ("dangerous", "suspicious"):
            for p in by_hash[h]:
                res["flagged"].append({"path": p, **{k: d.get(k) for k in ("verdict", "malicious", "suspicious", "engines",
                                                                          "threat", "link", "what", "sha256", "detections")}})
                if emit_events:
                    M.emit("virustotal", "high" if d["verdict"] == "dangerous" else "medium",
                           f"VirusTotal: {d['malicious']}/{d['engines']} detections" + (f" ({d['threat']})" if d.get("threat") else ""),
                           p, details=d["what"], uniq=f"vt|{h}|{p}", origin="scan")
        elif d["verdict"] == "clean":
            res["clean"] += len(by_hash[h])
        else:
            res["unknown"] += len(by_hash[h])
        for p in by_hash[h]:
            res["items"].append({"path": p, "sha256": h, "verdict": d["verdict"], "malicious": d.get("malicious", 0),
                                 "engines": d.get("engines", 0), "cached": bool(d.get("cached"))})
    progress(phase="virustotal", vt_done=len(order), vt_total=len(order))
    res["items"] = res["items"][:500]
    return res


def folder_job(jid: str, path: str, only_risky: bool, max_files: int) -> dict:
    t0 = time.time()
    cancelled = lambda: jid in M.JOB_CANCEL
    files, skipped = gather(path, only_risky)
    prog = lambda **p: M.set_progress(jid, **p)
    r = vt_files(jid, files, max_files, cancelled, prog)
    r.update(path=path, files=len(files), skipped_types=skipped, duration=round(time.time() - t0, 1),
             cancelled=cancelled(), usage=usage())
    return r


def _risky_first(files):
    pri = lambda p: (os.path.splitext(p)[1].lower() not in {".exe", ".dll", ".scr", ".msi", ".ps1", ".bat", ".cmd", ".vbs",
                                                             ".js", ".hta", ".jar", ".lnk", ".zip", ".rar", ".7z", ".iso"}, p)
    return sorted(files, key=pri)


def install_check_hook():
    orig = M.run_scan

    def run_scan(jid, targets, action="report", mode="scan"):
        c = cfg()
        if mode != "check" or not c["use_in_check"] or not api_key():
            return orig(jid, targets, action, mode)
        cancelled = lambda: jid in M.JOB_CANCEL
        roots = [r for r in M.expand_targets(targets) if os.path.exists(r)]
        files = []
        for r in roots:
            files += gather(r, c["only_risky"])[0]
        files = _risky_first(files)
        prog = lambda **p: M.set_progress(jid, **p)
        vt = {"checked": 0, "flagged": [], "skipped_limit": 0, "stopped": ""}
        try:
            vt = vt_files(jid, files, c["check_max"], cancelled, prog, emit_events=False)
        except Exception as e:
            M.log.exception("VirusTotal step of 'Is this safe?'")
            vt["stopped"] = str(e)
        try:
            res = orig(jid, targets, action, mode)
        except RuntimeError as e:          # no local engine: still report what VirusTotal found
            res = {"mode": mode, "action": "report", "targets": roots, "verdict": "clean", "cancelled": cancelled(),
                   "duration": 0, "stats": {"files": len(files), "scanned": 0, "excluded": 0, "too_big": 0, "unreadable": 0,
                                            "engine_errors": 0}, "found": 0, "files": [], "truncated": False,
                   "notes": [f"Local check couldn't run: {e}"], "engines": {}}
        merge(res, vt, len(files))
        return res

    M.run_scan = run_scan


def merge(res: dict, vt: dict, n_files: int):
    idx = {M.norm(f["path"]): f for f in res.get("files", [])}
    for f in vt.get("flagged", []):
        dang = f["verdict"] == "dangerous"
        reason = {"engine": "virustotal", "rule": f"VirusTotal {f['malicious']}/{f['engines']}" + (f" · {f['threat']}" if f.get("threat") else ""),
                  "level": "dangerous" if dang else "suspicious", "severity": "high" if dang else "medium", "what": f["what"]}
        tgt = idx.get(M.norm(f["path"]))
        if tgt is None:
            try:
                size = os.path.getsize(f["path"])
            except OSError:
                size = None
            running = len(M.find_processes(f["path"])) if hasattr(M, "find_processes") else 0
            tgt = {"path": f["path"], "reasons": [], "level": "suspicious", "quarantined": False, "size": size,
                   "sha256": f.get("sha256"), "running": running}
            res.setdefault("files", []).append(tgt)
            idx[M.norm(f["path"])] = tgt
        tgt["reasons"].insert(0, reason)
        tgt["vt_link"] = f.get("link")
        if dang:
            tgt["level"] = "dangerous"
        M.emit("virustotal", reason["severity"], reason["rule"], f["path"], details=f["what"],
               uniq=f"vt|{f.get('sha256')}|{f['path']}", origin="scan")
    files = res.get("files", [])
    files.sort(key=lambda f: (f["level"] != "dangerous", f["path"]))
    res["found"] = len(files)
    res["verdict"] = "dangerous" if any(f["level"] == "dangerous" for f in files) else "suspicious" if files else "clean"
    note = None
    if vt.get("stopped") and vt["stopped"] != "cancel":
        note = f"VirusTotal: {vt['stopped']}"
    elif vt.get("skipped_limit"):
        n = vt["skipped_limit"]
        note = (f"VirusTotal checked {vt['checked']} file{'s' if vt['checked'] != 1 else ''}. {n} more file{'s were' if n != 1 else ' was'} "
                f"only checked locally (you can raise this in Settings > VirusTotal > files per safety check).")
    if note:
        res.setdefault("notes", []).append(note)
    res["vt"] = {"checked": vt.get("checked", 0), "flagged": len(vt.get("flagged", [])), "unknown": vt.get("unknown", 0),
                 "clean": vt.get("clean", 0), "lookups": vt.get("lookups", 0), "cached": vt.get("cached", 0),
                 "skipped": vt.get("skipped_limit", 0), "stopped": vt.get("stopped", ""), "files": n_files,
                 "items": vt.get("items", [])[:200], "usage": usage()}


# --------------------------------------------------------------------------- #
# Submissions (link scan, file upload) - run as background jobs
# --------------------------------------------------------------------------- #
def submit_url_job(jid: str, url: str) -> dict:
    cancelled = lambda: jid in M.JOB_CANCEL
    M.set_progress(jid, phase="vt_submit", step="Sending the link to VirusTotal…")
    status, body = call("POST", "/urls", "submit-url", url, data=urllib.parse.urlencode({"url": url}).encode(),
                        ctype="application/x-www-form-urlencoded", wait=True, cancelled=cancelled)
    aid = (body.get("data") or {}).get("id")
    if status not in (200, 201) or not aid:
        raise VTError(((body or {}).get("error") or {}).get("message") or f"VirusTotal answered with error {status}.")
    M.set_progress(jid, phase="vt_submit", step="VirusTotal is checking the link (about a minute)…")
    d = poll_analysis(aid, "url", url, cancelled)
    return {"kind": "url", "key": url, "result": d or not_found("url", url), "pending": d is None, "usage": usage()}


def upload_job(jid: str, path: str) -> dict:
    cancelled = lambda: jid in M.JOB_CANCEL
    size = os.path.getsize(path)
    if size > MAX_UPLOAD:
        raise VTError("Files over 32 MB can't be uploaded from OmniShield. Use the VirusTotal website instead.")
    h = M.sha256(path)
    M.set_progress(jid, phase="vt_submit", step="Uploading the file to VirusTotal…")
    b = "----SC" + uuid.uuid4().hex
    with open(path, "rb") as f:
        content = f.read()
    name = os.path.basename(path).replace('"', "")
    data = (f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n').encode() + content + f"\r\n--{b}--\r\n".encode()
    status, body = call("POST", "/files", "upload", h, data=data, ctype=f"multipart/form-data; boundary={b}", wait=True, cancelled=cancelled)
    aid = (body.get("data") or {}).get("id")
    if status not in (200, 201) or not aid:
        raise VTError(((body or {}).get("error") or {}).get("message") or f"Upload failed (error {status}).")
    M.set_progress(jid, phase="vt_submit", step="VirusTotal is scanning the file (1-2 minutes)…")
    d = poll_analysis(aid, "file", h, cancelled)
    if d:
        d["sha256"] = h
    return {"kind": "file", "key": h, "path": path, "result": d or not_found("file", h), "pending": d is None, "usage": usage()}


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
class SettingsReq(BaseModel):
    api_key: str | None = None
    remove_key: bool = False
    plan: str | None = None
    per_min: int | None = None
    per_day: int | None = None
    per_month: int | None = None
    reserve: int | None = None
    use_in_check: bool | None = None
    check_max: int | None = None
    upload: str | None = None
    cache_days: int | None = None
    only_risky: bool | None = None
    folder_max: int | None = None


class LookupReq(BaseModel):
    kind: str
    value: str
    force: bool = False


class PathReq(BaseModel):
    path: str
    only_risky: bool | None = None
    max_files: int | None = None


def status_payload():
    k = api_key()
    return {"configured": bool(k), "key": mask(k), "cfg": cfg(), "usage": usage(),
            "privacy": "Files are identified only by their fingerprint unless you upload them. Links, websites and IP addresses you check are sent to VirusTotal."}


def api_status():
    return status_payload()


def api_settings(req: SettingsReq):
    c = {k: v for k, v in json.loads(_get("cfg", "{}") or "{}").items() if k in DEFAULTS}
    if req.remove_key:
        _set("key", "")
        _set("remote", "{}")
    if req.api_key is not None and req.api_key.strip():
        k = req.api_key.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", k):
            raise HTTPException(400, "A VirusTotal API key is 64 letters and numbers (0-9, a-f). Copy it again from your VirusTotal profile.")
        _set("key", _protect(k))
        _set("remote", "{}")
        _set("blocked_until", "0")
    if req.plan is not None:
        if req.plan not in ("free", "custom"):
            raise HTTPException(400, "plan must be free or custom")
        c["plan"] = req.plan
    for k, lo, hi in (("per_min", 1, 10000), ("per_day", 1, 10_000_000), ("per_month", 1, 300_000_000),
                      ("reserve", 0, 100000), ("check_max", 1, 1000), ("cache_days", 1, 90), ("folder_max", 1, 20000)):
        v = getattr(req, k)
        if v is not None:
            c[k] = max(lo, min(hi, int(v)))
    for k in ("use_in_check", "only_risky"):
        if getattr(req, k) is not None:
            c[k] = bool(getattr(req, k))
    if req.upload is not None:
        if req.upload not in ("never", "ask"):
            raise HTTPException(400, "upload must be never or ask")
        c["upload"] = req.upload
    _set("cfg", json.dumps(c))
    if req.api_key:
        threading.Thread(target=sync_quiet, daemon=True).start()
    return status_payload()


def api_test():
    if not api_key():
        raise HTTPException(400, "Add an API key first.")
    try:
        r = sync_remote()
    except VTError as e:
        raise HTTPException(502, str(e))
    if r.get("ok"):
        return {"ok": True, "message": "Your key works. Usage was synced from VirusTotal (this didn't use any lookups).", **status_payload()}
    if r.get("status") == 401:
        raise HTTPException(400, "VirusTotal didn't accept this API key.")
    try:  # fall back to one counted lookup of the harmless EICAR test file
        lookup("file", EICAR_SHA256, force=True)
        return {"ok": True, "message": "Your key works (this test used 1 lookup).", **status_payload()}
    except QuotaError as e:
        raise HTTPException(429, str(e))
    except VTError as e:
        raise HTTPException(400, str(e))


def _quota_resp(e: QuotaError):
    return JSONResponse(status_code=429, content={"detail": str(e), "wait": e.wait, "which": e.which, "usage": usage()})


def api_lookup(req: LookupReq):
    kind = req.kind if req.kind in ("file", "hash", "url", "domain", "ip", "path") else None
    if not kind:
        raise HTTPException(400, "kind must be path, hash, url, domain or ip")
    try:
        label = ""
        if kind == "path":
            p = os.path.normpath(os.path.expandvars(req.value.strip().strip('"')))
            if not os.path.isfile(p):
                raise VTError("Choose a file (for folders, use the Folder tab).")
            value, kind, label = M.sha256(p), "file", os.path.basename(p)
            if not value:
                raise VTError("Windows didn't allow reading this file.")
        else:
            value = norm_input(kind, req.value)
            label = "" if kind == "hash" else req.value.strip()[:200]
        d = lookup(kind, value, force=req.force, label=label)
        if req.kind == "path":
            d["path"] = p
            d["size_local"] = os.path.getsize(p)
            if d["verdict"] in ("dangerous", "suspicious"):
                M.emit("virustotal", "high" if d["verdict"] == "dangerous" else "medium",
                       f"VirusTotal: {d['malicious']}/{d['engines']} detections" + (f" ({d.get('threat')})" if d.get("threat") else ""),
                       p, details=d["what"], uniq=f"vt|{value}|{p}", origin="scan")
        d["usage"] = usage()
        d["can_upload"] = cfg()["upload"] == "ask"
        return d
    except QuotaError as e:
        return _quota_resp(e)
    except VTError as e:
        raise HTTPException(400, str(e))


def api_plan(req: PathReq):
    try:
        return plan(req.path, req.only_risky if req.only_risky is not None else cfg()["only_risky"], req.max_files)
    except VTError as e:
        raise HTTPException(400, str(e))


def api_folder(req: PathReq):
    if not api_key():
        raise HTTPException(400, "Add your VirusTotal API key in Settings > VirusTotal first.")
    p = os.path.normpath(os.path.expandvars(req.path.strip().strip('"')))
    if not os.path.exists(p):
        raise HTTPException(404, f"Not found: {p}")
    c = cfg()
    only = c["only_risky"] if req.only_risky is None else req.only_risky
    mx = int(req.max_files or c["folder_max"])
    label = "VirusTotal: " + (os.path.basename(p.rstrip("\\/")) or p)
    return {"job": M.start_job("virustotal", label, lambda jid: folder_job(jid, p, only, mx), pass_id=True)}


def api_submit_url(req: LookupReq):
    try:
        u = norm_input("url", req.value)
    except VTError as e:
        raise HTTPException(400, str(e))
    return {"job": M.start_job("virustotal", "VirusTotal: scan link", lambda jid: submit_url_job(jid, u), pass_id=True)}


def api_upload(req: PathReq):
    if cfg()["upload"] != "ask":
        raise HTTPException(403, "Uploading is turned off. You can allow it in Settings > VirusTotal.")
    p = os.path.normpath(os.path.expandvars(req.path.strip().strip('"')))
    if not os.path.isfile(p):
        raise HTTPException(404, "File not found")
    return {"job": M.start_job("virustotal", "VirusTotal: upload " + os.path.basename(p), lambda jid: upload_job(jid, p), pass_id=True)}


def api_history(limit: int = 60):
    with M.db() as con:
        rows = con.execute("SELECT kind,key,label,verdict,data,fetched FROM addon_vt_cache ORDER BY fetched DESC LIMIT ?",
                           (min(limit, 300),)).fetchall()
    out = []
    for r in rows:
        d = json.loads(r[4])
        out.append({"kind": r[0], "key": r[1], "label": r[2] or d.get("name") or "", "verdict": r[3], "malicious": d.get("malicious", 0),
                    "engines": d.get("engines", 0), "found": d.get("found"), "time": dt.datetime.fromtimestamp(r[5]).isoformat(timespec="seconds")})
    return out


def api_result(kind: str, key: str):
    with M.db() as con:
        r = con.execute("SELECT data, label FROM addon_vt_cache WHERE kind=? AND key=?", (kind, key)).fetchone()
    if not r:
        raise HTTPException(404, "Not in your saved results")
    d = json.loads(r[0])
    d["cached"] = True
    d["label"] = r[1]
    return d


def api_sync():
    try:
        r = sync_remote()
    except VTError as e:
        raise HTTPException(502, str(e))
    return {"ok": bool(r.get("ok")), **status_payload()}


def explain_vt(orig, e: dict) -> dict:
    x = orig({**e, "engine": "yara"})       # gives the file actions (quarantine, stop, block...)
    dang = e["severity"] in ("high", "critical")
    x.update(title="Flagged by VirusTotal" if dang else "Some security companies flag this file",
             what=(e.get("details") or "") + " VirusTotal checks a file's fingerprint against dozens of antivirus companies.",
             steps=(["Don't open or run this file.", "Quarantine it (button below). Nothing is deleted.",
                     "If it's running, stop it and block it.", "Run a Quick scan to look for related files."] if dang else
                    ["Don't open it until you're sure.", "If it's software you trust from the official website, it may be a false alarm - click 'Not a threat'.",
                     "Otherwise quarantine it."]),
             fp="A file flagged by only 1-2 companies is often a false alarm. 5 or more is rarely wrong.")
    return x


def register(app, main):
    global M
    M = main
    try:
        M.VERSION = "1.9"
        with M._db_lock, M.db() as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS addon_vt_calls(id INTEGER PRIMARY KEY, ts REAL, kind TEXT, target TEXT, status INTEGER);
            CREATE INDEX IF NOT EXISTS ix_vt_calls_ts ON addon_vt_calls(ts);
            CREATE TABLE IF NOT EXISTS addon_vt_cache(kind TEXT, key TEXT, label TEXT, verdict TEXT, data TEXT, fetched REAL,
                PRIMARY KEY(kind, key));
            """)
            con.execute("DELETE FROM addon_vt_calls WHERE ts < ?", (time.time() - 40 * 86400,))
        for path, fn, methods in (("/api/vt/status", api_status, ["GET"]), ("/api/vt/settings", api_settings, ["POST"]),
                                  ("/api/vt/test", api_test, ["POST"]), ("/api/vt/lookup", api_lookup, ["POST"]),
                                  ("/api/vt/plan", api_plan, ["POST"]), ("/api/vt/folder", api_folder, ["POST"]),
                                  ("/api/vt/submit-url", api_submit_url, ["POST"]), ("/api/vt/upload", api_upload, ["POST"]),
                                  ("/api/vt/history", api_history, ["GET"]), ("/api/vt/result", api_result, ["GET"]),
                                  ("/api/vt/sync", api_sync, ["POST"])):
            app.add_api_route(path, fn, methods=methods)
        install_check_hook()
        orig = M.explain_event
        M.explain_event = lambda e: explain_vt(orig, e) if e.get("engine") == "virustotal" else orig(e)

        def periodic_sync():
            while True:
                time.sleep(1800)
                try:
                    if api_key() and _count(time.time() - 1800):
                        sync_remote()
                except Exception:
                    pass
        threading.Thread(target=periodic_sync, daemon=True, name="vt-sync").start()
        M.log.info("Add-on 1.9 loaded (VirusTotal)")
    except Exception:
        M.log.exception("VirusTotal add-on registration failed")
