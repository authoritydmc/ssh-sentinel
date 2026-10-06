#!/usr/bin/env python3
"""SSH/auth security dashboard. Localhost only; SSO enforced by Traefik."""
import html
import ipaddress
import json
import os
import re
import socket
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOG = os.environ.get("AUTH_LOG", "/var/log/auth.log")
DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
HOSTS_DIR = os.path.join(DATA_DIR, "hosts")
AGENTS_FILE = os.path.join(DATA_DIR, "agents.json")
HOST_ID = os.environ.get("HOST_ID", socket.gethostname().split(".")[0])
MAX_LINES_PER_HOST = 60000
import hmac as _hmac  # noqa: E402


def _agents():
    try:
        with open(AGENTS_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def check_agent_token(host, token):
    agents = _agents()
    expect = agents.get(host, "")
    return bool(expect and token and _hmac.compare_digest(str(expect), str(token)))


def host_lines_path(host):
    safe = "".join(c if (c.isalnum() or c in "-_") else "_" for c in host)[:64] or "unknown"
    return os.path.join(HOSTS_DIR, safe + ".jsonl")


def store_pushed_lines(host, lines):
    os.makedirs(HOSTS_DIR, exist_ok=True)
    p = host_lines_path(host)
    with open(p, "a") as f:
        for ln in lines[:5000]:
            f.write((ln if ln.endswith("\n") else ln + "\n"))
    try:
        with open(p) as f:
            all_lines = f.readlines()
        if len(all_lines) > MAX_LINES_PER_HOST:
            with open(p, "w") as f:
                f.writelines(all_lines[-MAX_LINES_PER_HOST:])
            all_lines = all_lines[-MAX_LINES_PER_HOST:]
        with open(p + ".meta", "w") as f:
            json.dump({"host": host, "last_seen": time.time(), "lines": len(all_lines)}, f)
    except OSError:
        pass


def list_hosts():
    out = [{"id": HOST_ID, "local": True, "last_seen": time.time(), "online": True}]
    if os.path.isdir(HOSTS_DIR):
        for fn in sorted(os.listdir(HOSTS_DIR)):
            if not fn.endswith(".jsonl"):
                continue
            meta = {}
            try:
                with open(os.path.join(HOSTS_DIR, fn + ".meta")) as f:
                    meta = json.load(f)
            except (OSError, ValueError):
                pass
            last = meta.get("last_seen", 0)
            out.append({"id": fn[:-6], "local": False,
                        "last_seen": last, "lines": meta.get("lines", 0),
                        "online": (time.time() - last) < 120})
    return out
GEO_CACHE = "/tmp/sshlog_geo.json"
IP_CACHE = "/tmp/sshlog_ipcache.json"
IP_TTL = 7 * 86400
SPIDER = "http://dev-spiderfoot:5001"
RECON_MODULES = "sfp_dnsresolve,sfp_whois,sfp_ipapico,sfp_abusech"
RECON_TTL = 7 * 86400
# Event types worth showing inline (SpiderFoot result rows are
# [ts, data, source, module, .., type, ..]; ROOT + self-echo filtered out).
RECON_INTERESTING = ("GEOINFO", "DOMAIN_NAME", "INTERNET_NAME", "AFFILIATE_DOMAIN_NAME",
                     "BGP_AS_MEMBER", "BGP_AS_OWNER", "NETBLOCK_MEMBER", "NETBLOCK_OWNER",
                     "AFFILIATE_IPADDR", "IP_ADDRESS", "RAW_RIR_DATA", "ABUSECH_MALWARE",
                     "BLACKLISTED_IPADDR", "TOR_EXIT_NODE", "PROXY_HOST")


def spider(path, data=None, timeout=20):
    url = SPIDER + path
    if data is None:
        req = urllib.request.Request(url, headers={"User-Agent": "rajlabs-sshlog/3.0"})
        return json.load(urllib.request.urlopen(req, timeout=timeout))
    return http_form(url, data, timeout=timeout)


def recon_status(ip, force=False):
    """Auto-fire SpiderFoot recon for ip, cache results, report state.

    Returns dict(state= cached|started|running|done|error, ...). GET callers
    poll until state == done; results render inline in the sshlog modal.
    """
    key = "recon:" + ip
    ent = _cache.get(key, {})
    if ent.get("done") and not force and time.time() - ent.get("ts", 0) < RECON_TTL:
        ent["state"] = "cached"
        return ent
    try:
        scans = spider("/scanlist", timeout=15) or []
    except Exception as e:
        return {"state": "error", "error": "spiderfoot unreachable: " + type(e).__name__}
    sid = ent.get("scan") if ent.get("scan") and not force else None
    if not sid:
        for row in scans:
            # scanlist rows: [id, name, target, created, started, ended, status, ...]
            if len(row) > 6 and row[2] == ip and str(row[1]).startswith("sshlog:"):
                sid = row[0]
                break
    if not sid or force:
        try:
            r = spider("/startscan", {
                "scanname": "sshlog:%s" % ip, "scantarget": ip,
                "modulelist": RECON_MODULES, "typelist": "IP_ADDRESS",
                "usecase": "all"}, timeout=30)
            sid = r[1] if isinstance(r, list) and len(r) > 1 else None
            if not (isinstance(r, list) and r and r[0] == "SUCCESS" and sid):
                return {"state": "error", "error": "startscan rejected: " + str(r)[:120]}
            d = {"state": "started", "scan": sid, "done": False, "ts": time.time()}
            _cache[key] = d
            save_cache()
            return d
        except Exception as e:
            return {"state": "error", "error": "startscan failed: " + type(e).__name__}
    try:
        st = spider("/scanstatus?id=" + sid, timeout=15)
        status = st[5] if isinstance(st, list) and len(st) > 5 else "?"
    except Exception as e:
        return {"state": "error", "error": "scanstatus failed: " + type(e).__name__,
                "scan": sid}
    if status not in ("FINISHED", "ERROR-FAILED", "ABORTED"):
        return {"state": "running", "scan": sid, "status": status}
    try:
        rows = spider("/scaneventresults?id=" + sid + "&eventType=ALL", timeout=30) or []
    except Exception as e:
        return {"state": "error", "error": "results fetch failed: " + type(e).__name__,
                "scan": sid}
    seen, out = set(), []

    def _add(typ, data, mod):
        data = (data or "").strip()
        if not data or (typ, data) in seen:
            return
        seen.add((typ, data))
        out.append({"type": typ, "data": data[:300], "module": mod})

    # Baseline: sshlog's own enrichment always renders (SpiderFoot modules
    # are rate-limited / empty for bare scanner IPs, so never rely on them).
    try:
        base = ip_detail(ip)
        if base.get("city") or base.get("country"):
            _add("GEOINFO", ", ".join(x for x in
                [base.get("city"), base.get("country")] if x), "sshlog:geoip")
        _add("ORG", base.get("org") or base.get("isp"), "sshlog:geoip")
        _add("ASN", base.get("as"), "sshlog:geoip")
        _add("DOMAIN_NAME", base.get("ptr"), "sshlog:rdns")
        if base.get("rdap_name") or base.get("rdap_handle"):
            _add("NETBLOCK_OWNER", "%s %s %s" % (
                base.get("rdap_name", ""), base.get("rdap_handle", ""),
                base.get("rdap_cc", "")), "sshlog:rdap")
    except Exception:
        pass
    for r in rows:
        if not isinstance(r, list) or len(r) < 8:
            continue
        typ, data, mod = str(r[7]), str(r[1]), str(r[3])
        if typ in ("ROOT",) or (typ == "IP_ADDRESS" and data == ip):
            continue
        if typ not in RECON_INTERESTING:
            continue
        _add(typ, data, mod or "spiderfoot")
        if len(out) >= 60:
            break
    d = {"state": "done", "scan": sid, "status": status, "done": True,
         "ts": time.time(), "count": len(out), "results": out}
    _cache[key] = d
    save_cache()
    d["state"] = "done"
    return d
MONTHS = {m: i + 1 for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}

FAIL_RE = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)")
INVALID_RE = re.compile(r"Invalid user (\S+) from (\S+)")
ACCEPT_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)")
CLOSED_RE = re.compile(r"Connection closed by (\S+) port \d+")
DISC_RE = re.compile(r"Disconnected from (?:invalid user \S+ )?(\S+) [0-9.]+ port \d+")
TS_RE = re.compile(r"^(\w{3})\s+(\d+) (\d+):(\d+):(\d+)")
ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})")

_cache = {}
for _p in (GEO_CACHE, IP_CACHE):
    if os.path.exists(_p):
        try:
            _cache.update(json.load(open(_p)))
        except Exception:
            pass


def save_cache():
    try:
        json.dump({k: v for k, v in _cache.items() if k.startswith("geo:")},
                  open(GEO_CACHE, "w"))
        json.dump({k: v for k, v in _cache.items() if k.startswith("ip:")},
                  open(IP_CACHE, "w"))
    except Exception:
        pass


def flag(cc):
    if not cc or len(cc) != 2:
        return "\U0001F310"
    return chr(0x1F1E6 + ord(cc[0].upper()) - 65) + chr(0x1F1E6 + ord(cc[1].upper()) - 65)


def is_public_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)
    except ValueError:
        return False


_own_ips, _own_ts = set(), 0.0
OWN_TTL = 3600


def own_ips():
    """Host's own IPs (container + node egress/public) — excluded from attacker stats.

    Sources: hostname resolution, default-route source address, and optional
    SELF_PUBLIC_IPS env (comma-separated, for NAT hairpin where the log shows
    the node's public IP as the 'remote').
    """
    global _own_ips, _own_ts
    if _own_ips and time.time() - _own_ts < OWN_TTL:
        return _own_ips
    found = set()
    try:
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
        found.update(addrs)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        found.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    for part in os.environ.get("SELF_PUBLIC_IPS", "").split(","):
        part = part.strip()
        if part:
            found.add(part)
    _own_ips, _own_ts = found, time.time()
    return _own_ips


def http_json(url, data=None, timeout=12):
    req = urllib.request.Request(
        url, data=json.dumps(data).encode() if data is not None else None,
        headers={"Content-Type": "application/json",
                 "User-Agent": "rajlabs-sshlog/3.0"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def http_form(url, fields, timeout=20):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json",
                 "User-Agent": "rajlabs-sshlog/3.0"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def geo_lookup(ips):
    missing = [ip for ip in set(ips)
               if "geo:" + ip not in _cache and is_public_ip(ip)]
    if missing:
        try:
            res = http_json(
                "http://ip-api.com/batch?fields=query,status,country,countryCode,city,org,as,isp,hosting,proxy,lat,lon",
                [{"query": ip} for ip in missing[:100]], timeout=15)
            for r in res:
                if r.get("status") == "success":
                    _cache["geo:" + r["query"]] = {
                        "country": r.get("country", ""), "cc": r.get("countryCode", ""),
                        "city": r.get("city", ""), "org": r.get("org", ""),
                        "as": r.get("as", ""), "isp": r.get("isp", ""),
                        "lat": r.get("lat"), "lon": r.get("lon"),
                        "hosting": bool(r.get("hosting")), "proxy": bool(r.get("proxy")),
                        "ts": time.time()}
            save_cache()
        except Exception:
            pass
    return {ip: _cache.get("geo:" + ip, {}) for ip in ips}


def ip_detail(ip):
    """Cached enrichment: geo + rdap + reverse DNS."""
    if not is_public_ip(ip):
        return {"ip": ip, "private": True}
    key = "ip:" + ip
    ent = _cache.get(key, {})
    if ent and time.time() - ent.get("ts", 0) < IP_TTL and ent.get("done"):
        return ent
    d = {"ip": ip, "ts": time.time(), "done": True}
    d.update(geo_lookup([ip]).get(ip, {}))
    try:
        socket.setdefaulttimeout(4)
        d["ptr"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        d["ptr"] = ""
    try:
        r = http_json("https://rdap.org/ip/" + ip, timeout=10)
        d["rdap_name"] = r.get("name", "")
        d["rdap_handle"] = r.get("handle", "")
        d["rdap_cc"] = r.get("country", "")
        d["rdap_entities"] = [e.get("handle", "") for e in r.get("entities", [])][:5]
        d["rdap_updated"] = r.get("events", [{}])[-1].get("eventDate", "")[:10] \
            if r.get("events") else ""
    except Exception as e:
        d["rdap_error"] = type(e).__name__
    _cache[key] = d
    save_cache()
    return d


def parse_ts(ln, now):
    m = ISO_RE.match(ln)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                            int(m.group(4)), int(m.group(5)))
        except ValueError:
            return None
    m = TS_RE.match(ln)
    if not m:
        return None
    try:
        ts = datetime(now.year, MONTHS[m.group(1)], int(m.group(2)),
                      int(m.group(3)), int(m.group(4)))
        return ts.replace(year=now.year - 1) if ts > now + timedelta(days=1) else ts
    except (ValueError, KeyError):
        return None


def _epoch_ms(dt):
    return int(dt.timestamp() * 1000)


def _hour_ms(dt):
    return _epoch_ms(dt.replace(minute=0, second=0, microsecond=0))


def read_lines(host=None):
    """Local auth.log, or a joined agent's pushed lines. host='all' merges."""
    if not host or host == HOST_ID:
        try:
            with open(LOG, errors="replace") as f:
                return f.readlines()
        except OSError:
            return []
    if host == "all":
        merged = read_lines()
        if os.path.isdir(HOSTS_DIR):
            for fn in sorted(os.listdir(HOSTS_DIR)):
                if fn.endswith(".jsonl"):
                    try:
                        with open(os.path.join(HOSTS_DIR, fn)) as f:
                            merged.extend(f.readlines())
                    except OSError:
                        pass
        return merged
    try:
        with open(host_lines_path(host), errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


def summary(host=None):
    lines = read_lines(host)
    now = datetime.now()
    mine = own_ips()
    skipped_self = 0
    pair_counts, per_ip, hours, ok_hours = Counter(), Counter(), defaultdict(int), defaultdict(int)
    logins = []
    for ln in lines:
        m = FAIL_RE.search(ln) or INVALID_RE.search(ln)
        if m:
            if m.group(2) in mine:
                skipped_self += 1
                continue
            pair_counts[(m.group(1), m.group(2))] += 1
            per_ip[m.group(2)] += 1
            ts = parse_ts(ln, now)
            if ts:
                hours[_hour_ms(ts)] += 1
            continue
        m = CLOSED_RE.search(ln) or DISC_RE.search(ln)
        if m and is_public_ip(m.group(1)):
            if m.group(1) in mine:
                skipped_self += 1
                continue
            # Pre-auth probe with no username (scanner handshake / disconnect).
            pair_counts[("?", m.group(1))] += 1
            per_ip[m.group(1)] += 1
            ts = parse_ts(ln, now)
            if ts:
                hours[_hour_ms(ts)] += 1
            continue
        m = ACCEPT_RE.search(ln)
        if m:
            ts = parse_ts(ln, now)
            if ts:
                ok_hours[_hour_ms(ts)] += 1
            logins.append({"user": m.group(1), "ip": m.group(2),
                           "ts": _epoch_ms(ts) if ts else None})
    cc = {ip: _cache.get("geo:" + ip, {}) for ip in per_ip}
    top = []
    for (u, ip), c in pair_counts.most_common(25):
        g = cc.get(ip, {})
        rc = _cache.get("recon:" + ip, {})
        top.append({"user": u, "ip": ip, "hits": c,
                    "flag": flag(g.get("cc", "")), "cc": g.get("cc", ""),
                    "country": g.get("country", ""), "city": g.get("city", ""),
                    "org": g.get("org", "") or g.get("isp", ""),
                    "lat": g.get("lat"), "lon": g.get("lon"),
                    "recon": {"state": rc.get("state", ""),
                              "count": rc.get("count", 0) if rc.get("done") else 0}})
    tl = []
    for i in range(47, -1, -1):
        h = _hour_ms(now - timedelta(hours=i))
        tl.append([h, hours.get(h, 0), ok_hours.get(h, 0)])
    return {"total": sum(per_ip.values()), "ips": len(per_ip), "top": top,
            "timeline": tl, "logins": logins[-60:],
            "excluded_self": skipped_self, "self_ips": sorted(mine),
            "geo_cached": sum(1 for k in _cache if k.startswith("geo:")),
            "now": _epoch_ms(now), "host": host or HOST_ID,
            "hosts": list_hosts()}


def ip_history(ip, lines=None, host=None):
    lines = read_lines(host) if lines is None else lines
    now = datetime.now()
    users, hits, first, last, hours = Counter(), 0, None, None, defaultdict(int)
    for ln in lines:
        if ip not in ln:
            continue
        m = FAIL_RE.search(ln) or INVALID_RE.search(ln)
        if m and m.group(2) == ip:
            users[m.group(1)] += 1
            hits += 1
            ts = parse_ts(ln, now)
            if ts:
                first = ts if not first or ts < first else first
                last = ts if not last or ts > last else last
                hours[_hour_ms(ts)] += 1
    tl = sorted(hours.items())[-48:]
    return {"users": users.most_common(10), "hits": hits,
            "first": _epoch_ms(first) if first else None,
            "last": _epoch_ms(last) if last else None,
            "timeline": tl}


PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'>
<title>SSH Security Dashboard</title>
<style>
:root{--bg:#0b0e14;--card:#151b26;--line:#232c3d;--txt:#dbe4f0;--dim:#8b98ad;--acc:#58a6ff;--bad:#f85149;--ok:#3fb950}
*{box-sizing:border-box}body{background:var(--bg);color:var(--txt);font:14px/1.5 system-ui,sans-serif;margin:0;padding:20px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--dim);margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.stat b{font-size:24px;display:block}.stat span{color:var(--dim);font-size:12px}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
@media(max-width:900px){.cards{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;min-width:0}
.card h3{margin:0 0 10px;font-size:15px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.stat{transition:border-color .2s,transform .2s}
.stat:hover{border-color:var(--acc);transform:translateY(-1px)}
.stat b{background:linear-gradient(180deg,#fff,#9ec5ff);-webkit-background-clip:text;background-clip:text;color:transparent}
.chart{display:flex;gap:6px}
.yaxis{display:flex;flex-direction:column;justify-content:space-between;font-size:10px;color:var(--dim);text-align:right;padding:2px 0 0}
.bars{flex:1;display:flex;align-items:flex-end;gap:2px;height:150px;border-left:1px solid var(--line);border-bottom:1px solid var(--line);padding:4px 2px 0}
.cbar{flex:1;display:flex;align-items:flex-end;height:100%;min-width:2px}
.cbar i{display:block;width:100%;border-radius:2px 2px 0 0;background:linear-gradient(180deg,#58a6ff,#1c3d5a);min-height:2px}
.cbar i.pk{background:linear-gradient(180deg,#ff7b72,#a40e26)}
.cbar i.zero{background:#232c3d;opacity:.5}
.xaxis{display:flex;gap:2px;margin:4px 0 0 30px;font-size:10px;color:var(--dim)}
.xaxis div{flex:1;white-space:nowrap;overflow:visible}
body{background:radial-gradient(1200px 400px at 20% -10%,#16233a 0%,var(--bg) 55%) fixed,var(--bg)}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left}
th{color:var(--dim);font-weight:600;font-size:12px}
tr.ip{cursor:pointer}tr.ip:hover td{background:#1c2534}
.bar{display:flex;align-items:flex-end;gap:2px;height:90px;margin-top:6px}
.bar div{flex:1;background:linear-gradient(180deg,var(--acc),#1c3d5a);border-radius:2px 2px 0 0;min-height:2px;position:relative}
.tlab{position:absolute;bottom:-16px;left:50%;transform:translateX(-50%);font-size:10px;color:var(--dim);white-space:nowrap}
#tl{margin-bottom:18px}
#net{width:100%;height:380px;border-radius:8px;background:#0d1320;display:block}
.logbox{background:#0d1320;border:1px solid var(--line);border-radius:8px;padding:8px 0;overflow:auto;font:12px/1.65 ui-monospace,monospace;max-height:420px}
.logbox div{padding:1px 12px;white-space:pre-wrap;word-break:break-all;border-left:3px solid transparent}
.logbox div:hover{background:#1c2534}
.lf-bad{color:#ff9d97;border-left-color:#f85149 !important;background:rgba(248,81,73,.06)}
.lf-ok{color:#7ee787;border-left-color:#3fb950 !important}
.lf-auth{color:#a5d6ff}
.lf-dim{color:#8b98ad}
form{display:flex;gap:8px;margin:10px 0;flex-wrap:wrap}
input,button{background:#0d1320;border:1px solid var(--line);color:var(--txt);border-radius:6px;padding:7px 10px;font-size:13px}
button{background:#1c3d5a;cursor:pointer}a{color:var(--acc)}
.pill{display:inline-block;background:#1c3d5a;border-radius:20px;padding:1px 9px;font-size:12px}
#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:10;overflow:auto}
#mbox{background:var(--card);border:1px solid var(--line);border-radius:12px;max-width:720px;margin:5vh auto;padding:20px}
#mbox h2{margin-top:0}.kv{display:grid;grid-template-columns:130px 1fr;gap:4px 10px;font-size:13px;margin:10px 0}
.kv b{color:var(--dim);font-weight:600}.x{float:right;cursor:pointer;font-size:18px;color:var(--dim)}
.tag{background:#3a2b12;color:#f0b429;border-radius:4px;padding:0 6px;font-size:12px;margin-right:4px}
#err{display:none;background:#3a1414;border:1px solid #f85149;color:#ffb4b4;border-radius:8px;padding:10px 14px;margin-bottom:12px}
.spin{color:var(--dim)}
body{padding-bottom:44px}
#statusbar{position:fixed;left:0;right:0;bottom:0;z-index:5;background:rgba(13,19,32,.96);border-top:1px solid var(--line);font-size:12px;color:var(--dim);padding:7px 16px;display:flex;gap:18px;flex-wrap:wrap}
#statusbar b{color:var(--txt);font-weight:600}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:6px;vertical-align:baseline}
.dot.busy{background:#d29922;animation:blink 1s infinite alternate}
@keyframes blink{to{opacity:.3}}
</style></head><body>
<h1>\U0001F6E1\uFE0F SSH Security Dashboard</h1>
<div class=sub>live from <span class=pill>/var/log/auth.log</span> &nbsp;<a href="/">container logs (dozzle)</a>
&ensp;click any attacker IP for full intel &middot; <span class=sub>times in your timezone: <b id=tz>…</b></span></div>
<div id=err></div>
<div class=grid id=stats></div>
<div class=cards>
<div class=card><h3>\U0001F310 Attack network <span style="color:var(--dim);font-weight:400">(flags = origin countries, ring = wanted user — drag to rotate, click an IP)</span></h3><canvas id=net></canvas></div>
<div class=card><h3>\U0001F4CA Attacks per hour (48h) <span class=sub id=tlcap></span></h3><div id=tl></div></div>
</div>
<div class=cards>
<div class=card><h3>\U0001F3F4\u200D\u2620\uFE0F Top attackers</h3><table id=atk></table></div>
<div class=card><h3>\u2705 Successful logins</h3><table id=ok></table></div>
</div>
<div class=card><h3>\U0001F9FE Raw log <span class=sub id=logmeta></span></h3>
<form onsubmit="return tail()"><input id=q placeholder="filter, e.g. Accepted or an IP" size=34>
<input id=n value=200 size=5><button>tail</button>
<button type=button id=ordbtn onclick="toggleOrder()">\u2193 newest first</button></form><div id=log class=logbox></div></div>
<div id=modal><div id=mbox></div></div>
<div id=statusbar><span><span class=dot id=dot></span><b id=sb-state>starting…</b></span><span id=sb-geo></span><span id=sb-self></span><span id=sb-log></span><span id=sb-tail></span><span id=sb-next></span></div>
<script>
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const BASE=new URL('.',location.href).pathname.replace(/\\/?$/,'/');
let TOP=[];
function showErr(m){const e=document.getElementById('err');e.style.display='block';
 e.innerHTML+='<div>'+esc(m)+'</div>';}
async function jget(p){
 const r=await fetch(BASE+p);
 if(!r.ok)throw new Error(p+' → HTTP '+r.status);
 return r.json();
}
function setSb(id,txt){document.getElementById(id).innerHTML=txt;}
function setBusy(b){
 document.getElementById('dot').className='dot'+(b?' busy':'');
 setSb('sb-state',b?'working…':'live');
}
const TZ=Intl.DateTimeFormat().resolvedOptions().timeZone||'local';
const fmtT=e=>e?new Date(e).toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}):'—';
const fmtH=e=>new Date(e).toLocaleString([],{day:'numeric',hour:'2-digit'});
const fmtClock=e=>e?new Date(e).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'}):'';
function relT(e){
 if(!e)return '—';
 const s=Math.max(0,(Date.now()-e)/1000);
 if(s<60)return 'just now';
 const m=s/60;if(m<60)return `${Math.floor(m)}m ago`;
 const h=m/60;if(h<24)return `${Math.floor(h)}h ago`;
 const d=h/24;if(d<30)return `${Math.floor(d)}d ago`;
 return fmtT(e);
}
function chartHTML(tl,mx){
 // Pure-HTML chart (no SVG string parsing, no canvas): y-axis + bars + x labels.
 const rows=[mx,Math.round(mx/2),0].map(v=>`<div>${v}</div>`).join('');
 const bars=tl.map(t=>{
  const h=t[1]/mx*100;
  const peak=t[1]===mx&&mx>0;
  return `<div class=cbar title="${fmtH(t[0])}: ${t[1]} attacks">`+
   `<i style="height:${Math.max(3,h)}%" class="${peak?'pk':t[1]?'':'zero'}"></i></div>`;
 }).join('');
 const xl=tl.map((t,i)=>(i%12===0||i===tl.length-1)?`<div>${fmtH(t[0])}</div>`:'<div></div>').join('');
 return `<div class=chart><div class=yaxis>${rows}</div><div class=bars>${bars}</div></div><div class=xaxis><div></div>${xl}</div>`;
}
function flagImg(cc,sz){
 cc=(cc||'').toLowerCase();
 if(!/^[a-z]{2}$/.test(cc))return '<span style="font-size:18px">🌐</span>';
 sz=sz||22;
 return `<img src="https://flagcdn.com/w40/${cc}.png" width="${sz}" style="border-radius:3px;vertical-align:middle" loading="lazy" onerror="this.outerHTML='🌐'">`;
}
async function load(){
 setBusy(true);
 document.getElementById('tz').textContent=TZ;
 try{
  const d=await jget('api/summary');
  TOP=d.top||[];
  document.getElementById('stats').innerHTML=
   `<div class=stat><b>${d.total}</b><span>failed attempts${d.excluded_self?' <span class=sub>(+'+d.excluded_self+' self excluded)</span>':''}</span></div>
    <div class=stat><b>${d.ips}</b><span>attacker IPs</span></div>
    <div class=stat><b>${(d.logins||[]).length}</b><span>successful logins</span></div>`;
  document.getElementById('atk').innerHTML='<tr><th></th><th>user</th><th>ip</th><th>hits</th><th>origin</th><th>recon</th></tr>'+
   TOP.map(t=>{
    const loc=[t.city,t.country].filter(Boolean).join(', ')||t.cc||'—';
    const org=t.org?` <span class=sub>${esc(t.org.slice(0,28))}</span>`:'';
    const rb=t.recon&&t.recon.count?`<span class=tag>🔍 ${t.recon.count}</span>`:(t.recon&&t.recon.state?'<span class=sub>…</span>':'');
    return `<tr class=ip onclick="ipinfo('${esc(t.ip)}')"><td>${flagImg(t.cc)}</td><td>${esc(t.user)}</td><td>${esc(t.ip)}</td><td>${t.hits}</td><td>${esc(loc)}${org}</td><td>${rb}</td></tr>`;}).join('')||'<tr><td colspan=6 class=spin>no attacker IPs found</td></tr>';
  const lg=(d.logins||[]).slice(-15).reverse();
  document.getElementById('ok').innerHTML='<tr><th>user</th><th>ip</th><th>time</th></tr>'+
   (lg.map(l=>`<tr><td>${esc(l.user)}</td><td>${esc(l.ip)}</td><td title="${l.ts?new Date(l.ts).toLocaleString():''}">${fmtT(l.ts)}</td></tr>`).join('')||'<tr><td colspan=3 class=spin>no successful logins in range</td></tr>');
  const tl=d.timeline||[];
  const mx=Math.max(1,...tl.map(t=>t[1]));
  const peak=tl.reduce((a,t)=>t[1]>a[1]?t:a,[0,0]);
  document.getElementById('tl').innerHTML=chartHTML(tl,mx);
  document.getElementById('tlcap').textContent=`peak ${mx}/h · ${fmtH(peak[0])}`;
  const bycc={},byuser={};
  TOP.forEach(t=>{bycc[t.cc||'?']=(bycc[t.cc||'?']||0)+t.hits;byuser[t.user]=(byuser[t.user]||0)+t.hits;});
  const topcc=Object.entries(bycc).sort((a,b)=>b[1]-a[1])[0]||['?',0];
  const topuser=Object.entries(byuser).sort((a,b)=>b[1]-a[1])[0]||['?',0];
  document.getElementById('stats').innerHTML+=
   `<div class=stat><b>${mx}/h</b><span>peak hour</span></div>
    <div class=stat><b>${esc(topcc[0])}</b><span>top origin (${topcc[1]} hits)</span></div>
    <div class=stat><b>${esc(topuser[0])}</b><span>most-targeted user (${topuser[1]} tries)</span></div>`;
  try{drawNet(TOP);}catch(e){showErr('attack graph unavailable: '+e.message);}
  setSb('sb-geo',`🌍 geo cache: <b>${d.geo_cached||0}</b> IPs`);
  setSb('sb-self',`🛡️ self excluded: <b>${d.excluded_self||0}</b>`);
  setSb('sb-log',`🧾 summary at <b>${fmtClock(d.now)}</b>`);
 }catch(e){showErr('summary failed: '+e.message+' — is the /ssh route reaching the viewer?');}
 setBusy(false);
 try{await tail();}catch(e){showErr('log tail failed: '+e.message);}
}
let NEXT=60;
setInterval(()=>{NEXT--;if(NEXT<=0){NEXT=60;load();}else setSb('sb-next',`⏱ refresh in <b>${NEXT}s</b>`);},1000);
async function ipinfo(ip){
 const box=document.getElementById('mbox');
 CUR_IP=ip;
 document.getElementById('modal').style.display='block';
 box.innerHTML='<h2>'+esc(ip)+'</h2><p class=spin>resolving intel…</p>';
 let d;
 try{d=await jget('api/ipinfo?ip='+encodeURIComponent(ip));}
 catch(e){box.innerHTML='<span class=x onclick="closem()">✕</span><h2>'+esc(ip)+'</h2><p>intel lookup failed: '+esc(e.message)+'</p>';return;}
 if(d.private){box.innerHTML=`<span class=x onclick="closem()">\u2715</span><h2>${esc(ip)}</h2><p>private / local address \u2014 no external intel.</p>`;return;}
 const tags=(d.hosting?'<span class=tag>HOSTING/DC</span>':'')+(d.proxy?'<span class=tag>PROXY/VPN</span>':'');
 const users=d.history.users.map(u=>`${esc(u[0])} (${u[1]})`).join(', ')||'\u2014';
 const mx=Math.max(1,...d.history.timeline.map(t=>t[1]));
  const bars=d.history.timeline.map(t=>`<div style="height:${Math.max(3,100*t[1]/mx)}%" title="${fmtH(t[0])}: ${t[1]}"></div>`).join('');
 box.innerHTML=`<span class=x onclick="closem()">\u2715</span>
 <h2 style="font-size:28px">${d.flag||''} ${esc(ip)} ${tags}</h2>
 <div class=kv>
 <b>Location</b><span>${esc(d.city||'')}${d.city&&d.country?', ':''}${esc(d.country||'')} ${esc(d.cc||'')}</span>
 <b>Org / ISP</b><span>${esc(d.org||d.isp||'\u2014')}</span>
 <b>ASN</b><span>${esc(d.as||'\u2014')}</span>
 <b>rDNS</b><span>${esc(d.ptr||'\u2014')}</span>
 <b>RDAP net</b><span>${esc(d.rdap_name||'')} ${esc(d.rdap_handle||'')} ${esc(d.rdap_cc||'')}</span>
  <b>Local hits</b><span>${d.history.hits} attempts &middot; first ${fmtT(d.history.first)} (${relT(d.history.first)}) &middot; last ${fmtT(d.history.last)} (${relT(d.history.last)})</span>
  <b>Users tried</b><span>${users}</span>
  </div>
  <h3>\U0001F9F5 Attack chain <span class=sub>every log line for this IP, newest first</span></h3>
  <p><button onclick="chainLogs()">\U0001F50D show full log chain</button>
  <span id=chainmeta style="color:var(--dim)"></span></p>
  <div id=chain class=logbox style="max-height:300px"></div>
  <h3>Activity (48h)</h3><div class=bar>${bars}</div>
  <h3>\U0001F50D Recon <span class=sub id=reconsub>(auto-started, cached 7d)</span></h3>
  <div id=recon><p class=spin>starting recon…</p></div>
  <p><button onclick="recon(true)">\u21BB re-run recon</button>
  <span id=rej style="color:var(--dim)"></span></p>
  <p class=sub>intel cached 7d &middot; sources: ip-api.com, RDAP, rDNS, SpiderFoot, local auth.log</p>`;
  pollRecon(ip);
}
function closem(){document.getElementById('modal').style.display='none'}
document.getElementById('modal').addEventListener('click',e=>{if(e.target.id==='modal')closem()});
let RECON_TIMER=null, CUR_IP=null;
function reconRows(r){
 if(!r.results||!r.results.length)
  return '<p class=spin>scan finished with no notable findings (target may be a bare scanner IP).</p>';
 return '<table><tr><th>type</th><th>finding</th><th>module</th></tr>'+
  r.results.map(x=>`<tr><td><span class=pill>${esc(x.type)}</span></td><td>${esc(x.data)}</td><td class=sub>${esc(x.module)}</td></tr>`).join('')+'</table>';
}
async function pollRecon(ip,force){
 const box=document.getElementById('recon');
 if(RECON_TIMER){clearInterval(RECON_TIMER);RECON_TIMER=null;}
 if(force)box.innerHTML='<p class=spin>re-running recon…</p>';
 let tries=0;
 const once=async()=>{
  tries++;
  let r;
  try{
   r=await (await fetch(BASE+'api/recon?ip='+encodeURIComponent(ip)+(force?'&force=1':''),{method:'POST'})).json();
  }catch(e){box.innerHTML='<p>recon failed: '+esc(e.message)+'</p>';return true;}
  force=false;
  if(r.error){box.innerHTML='<p>recon failed: '+esc(r.error)+'</p>';return true;}
  const tag=r.state==='cached'?' (cached)':r.state==='done'?'':' — '+esc(r.state||r.status||'running')+'…';
  document.getElementById('reconsub').textContent=r.state==='cached'?'(cached result)':'(scan '+esc(r.scan||'?')+')';
  if(r.state==='done'||r.state==='cached'){
   box.innerHTML='<p class=sub>'+r.count+' findings &middot; scan '+esc(r.scan||'?')+'</p>'+reconRows(r);
   return true;
  }
  box.innerHTML='<p class=spin>recon '+esc(r.state||'running')+'… (scan '+esc(r.scan||'?')+') auto-refreshing</p>';
  return tries>=24;
 };
 if(await once())return;
 RECON_TIMER=setInterval(async()=>{if(await once()){clearInterval(RECON_TIMER);RECON_TIMER=null;}},5000);
}
async function recon(force){
 if(!CUR_IP)return;
 document.getElementById('rej').textContent='';
 pollRecon(CUR_IP,!!force);
}
async function chainLogs(){
 if(!CUR_IP)return;
 const box=document.getElementById('chain');
 box.innerHTML='<div class=lf-dim>loading chain…</div>';
 try{
  const r=await fetch(BASE+'api/tail?q='+encodeURIComponent(CUR_IP)+'&n=500');
  if(!r.ok)throw new Error('HTTP '+r.status);
  const lines=(await r.text()).split('\\n').filter(x=>x.trim()!=='');
  lines.reverse();
  document.getElementById('chainmeta').textContent=`${lines.length} lines`;
  box.innerHTML=lines.length?lines.map(ln=>`<div class="${colorLine(ln)}">${esc(ln)}</div>`).join(''):'<div class=lf-dim>no lines for this IP</div>';
  box.scrollTop=0;
 }catch(e){box.innerHTML='<div class=lf-bad>chain failed: '+esc(e.message)+'</div>';}
}
let LOG_NEWEST_FIRST=true;
function toggleOrder(){
 LOG_NEWEST_FIRST=!LOG_NEWEST_FIRST;
 document.getElementById('ordbtn').textContent=LOG_NEWEST_FIRST?'\u2193 newest first':'\u2191 oldest first';
 tail();
 return false;
}
function colorLine(ln){
 const l=ln.toLowerCase();
 if(/failed|invalid user|disconnected|connection closed|bye bye|error|denied|failure/.test(l))return 'lf-bad';
 if(/accepted|session opened|success/.test(l))return 'lf-ok';
 if(/sudo:|pam_unix|session/.test(l))return 'lf-auth';
 return 'lf-dim';
}
async function tail(){
 const q=document.getElementById('q').value,n=document.getElementById('n').value||200;
 const el=document.getElementById('log');
 setBusy(true);
 try{
  const r=await fetch(BASE+'api/tail?q='+encodeURIComponent(q)+'&n='+n);
  if(!r.ok)throw new Error('HTTP '+r.status);
  const t=await r.text();
  const lines=t.split('\\n').filter(x=>x.trim()!=='');
  if(!lines.length){el.innerHTML='<div class=lf-dim>(no matching lines — try clearing the filter)</div>';}
  else{
   if(LOG_NEWEST_FIRST)lines.reverse();
   el.innerHTML=lines.map(ln=>`<div class="${colorLine(ln)}">${esc(ln)}</div>`).join('');
   el.scrollTop=LOG_NEWEST_FIRST?0:el.scrollHeight;
  }
  document.getElementById('logmeta').textContent=`${lines.length} lines · ${LOG_NEWEST_FIRST?'newest first':'oldest first'} · ${fmtClock(Date.now())}`;
  setSb('sb-tail',`🧾 log tail: <b>${lines.length}</b> lines`);
 }catch(e){el.innerHTML='<div class=lf-bad>tail error: '+esc(e.message)+'</div>';}
 setBusy(false);
 return false;
}
const FLAG_CACHE={};
function flagImage(cc){
 cc=(cc||'').toLowerCase();
 if(!/^[a-z]{2}$/.test(cc))return null;
 if(!FLAG_CACHE[cc]){
  const im=new Image();
  im.src=`https://flagcdn.com/w80/${cc}.png`;
  FLAG_CACHE[cc]=im;
 }
 const im=FLAG_CACHE[cc];
 return (im.complete&&im.naturalWidth)?im:null;
}
function drawNet(top){
 // Hierarchical attack graph, zero deps: server → country (real flag) → IPs.
 // Country ring reveals coordinated campaigns; IP ring color = most-targeted
 // user (same color on distant nodes hints at one actor, many IPs).
 const cv=document.getElementById('net');
 const box=cv.parentElement,W=box.clientWidth-28||600,H=400;
 cv.width=W;cv.height=H;cv.style.width='100%';
 const ctx=cv.getContext('2d');
 const cx=W/2,cy=H/2,R=Math.min(W,H)/2-30;
 const UC=['#58a6ff','#f0883e','#3fb950','#d29922','#a371f7','#39c5cf','#ff7b72','#7ee787'];
 const ucol={};let ui=0;
 const ucolor=u=>ucol[u]||(ucol[u]=UC[ui++%UC.length]);
 // aggregate top entries by country (top[] is per user+ip; merge per ip)
 const byip={};
 top.slice(0,40).forEach(t=>{
  const e=byip[t.ip]||(byip[t.ip]={ip:t.ip,hits:0,cc:t.cc,country:t.country,city:t.city,user:t.user});
  e.hits+=t.hits;
 });
 const bycc={};
 Object.values(byip).forEach(e=>{
  const c=e.cc||'?';
  (bycc[c]||(bycc[c]={cc:c,country:e.country,hits:0,ips:[]})).hits+=e.hits;
  bycc[c].ips.push(e);
 });
 const countries=Object.values(bycc).sort((a,b)=>b.hits-a.hits).slice(0,10);
 countries.forEach((c,i)=>{
  c.a=i/Math.max(countries.length,1)*Math.PI*2-Math.PI/2;
  c.ips.sort((a,b)=>b.hits-a.hits);
  c.ips=c.ips.slice(0,8);
  c.ips.forEach((e,j)=>{
   e.da=(j-(c.ips.length-1)/2)*.42;
   e.rad=4+Math.min(11,Math.log10(1+e.hits)*4.5);
  });
  c.rad=13+Math.min(15,Math.log10(1+c.hits)*6);
 });
 let rot=0,drag=false,px=0,hover=null;
 const P=(c,a,r)=>[cx+Math.cos(a)*r,cy+Math.sin(a)*r*.82];
 function nodeXY(c,e){
  const a=c.a+rot+(e?e.da:0),r=e?R:R*.55;
  return P(c,a,r);
 }
 function draw(){
  ctx.clearRect(0,0,W,H);
  ctx.textAlign='center';
  ctx.beginPath();ctx.arc(cx,cy,13,0,7);ctx.fillStyle='#3fb950';ctx.fill();
  ctx.fillStyle='#0b0e14';ctx.font='bold 11px system-ui';ctx.fillText('YOU',cx,cy+4);
  countries.forEach(c=>{
   const [ccx,ccy]=nodeXY(c);
   c.x=ccx;c.y=ccy;
   ctx.beginPath();ctx.moveTo(cx,cy);ctx.lineTo(ccx,ccy);
   ctx.strokeStyle='rgba(88,166,255,.28)';ctx.lineWidth=1+Math.min(3,Math.log10(1+c.hits));ctx.stroke();
   const fim=flagImage(c.cc);
   if(fim){
    const fw=c.rad*2.4,fh=fw*0.72;
    ctx.save();
    ctx.beginPath();
    if(ctx.roundRect)ctx.roundRect(ccx-fw/2,ccy-fh/2,fw,fh,4);else ctx.rect(ccx-fw/2,ccy-fh/2,fw,fh);
    ctx.clip();
    ctx.drawImage(fim,ccx-fw/2,ccy-fh/2,fw,fh);
    ctx.restore();
    if(c===hover.c){ctx.strokeStyle='#fff';ctx.lineWidth=2;ctx.strokeRect(ccx-fw/2,ccy-fh/2,fw,fh);}
   }else{
    ctx.beginPath();ctx.arc(ccx,ccy,c.rad*.7,0,7);
    ctx.fillStyle='#58a6ff';ctx.fill();
    ctx.fillStyle='#fff';ctx.font='bold 10px system-ui';
    ctx.fillText((c.cc||'?').toUpperCase(),ccx,ccy+3);
   }
   ctx.fillStyle='#8b98ad';ctx.font='10px system-ui';
   const nm=c.country||c.cc||'?';
   ctx.fillText(`${nm} · ${c.hits}`,ccx,ccy+c.rad*.7+22);
   c.ips.forEach(e=>{
    const [ex,ey]=nodeXY(c,e);
    e.x=ex;e.y=ey;
    ctx.beginPath();ctx.moveTo(ccx,ccy);ctx.lineTo(ex,ey);
    ctx.strokeStyle='rgba(139,152,173,.3)';ctx.lineWidth=1;ctx.stroke();
    ctx.beginPath();ctx.arc(ex,ey,hover&&hover.e===e?e.rad+3:e.rad,0,7);
    ctx.fillStyle='#151b26';ctx.fill();
    ctx.lineWidth=2.5;ctx.strokeStyle=ucolor(e.user);ctx.stroke();
    ctx.fillStyle='#dbe4f0';ctx.font='9px ui-monospace,monospace';
    const short=e.ip.split('.').slice(-1)[0];
    ctx.fillText(short,ex,ey+e.rad+10);
   });
  });
  if(hover){
   const label=hover.e?`${hover.e.ip} · ${hover.e.hits} hits · wants '${hover.e.user}' · ${hover.e.city||hover.e.country||''}`
    :`${hover.c.country||hover.c.cc} · ${hover.c.hits} hits · ${hover.c.ips.length} IPs`;
   ctx.font='12px system-ui';
   const tw=ctx.measureText(label).width+16;
   const hx=hover.e?hover.e.x:hover.c.x,hy=hover.e?hover.e.y:hover.c.y;
   const bx=Math.min(Math.max(hx-tw/2,4),W-tw-4),by=hy-34,bh=22,r=6;
   ctx.fillStyle='rgba(21,27,38,.95)';ctx.strokeStyle='#58a6ff';
   ctx.beginPath();
   ctx.moveTo(bx+r,by);ctx.arcTo(bx+tw,by,bx+tw,by+bh,r);ctx.arcTo(bx+tw,by+bh,bx,by+bh,r);
   ctx.arcTo(bx,by+bh,bx,by,r);ctx.arcTo(bx,by,bx+tw,by,r);ctx.closePath();
   ctx.fill();ctx.stroke();
   ctx.fillStyle='#dbe4f0';ctx.fillText(label,bx+tw/2,hy-19);
  }
  // legend: user colors
  ctx.textAlign='left';ctx.font='10px system-ui';
  let lx=8;const ly=H-12;
  ctx.fillStyle='#8b98ad';ctx.fillText('wants:',lx,ly);lx+=44;
  Object.entries(ucol).slice(0,6).forEach(([u,col])=>{
   ctx.fillStyle=col;ctx.beginPath();ctx.arc(lx,ly-3,4,0,7);ctx.fill();
   ctx.fillStyle='#8b98ad';ctx.fillText(u,lx+7,ly);lx+=7+ctx.measureText(u).width+12;
  });
 }
 (function anim(){if(!drag)rot+=.0012;draw();requestAnimationFrame(anim);})();
 const pos=e=>{const b=cv.getBoundingClientRect();
  return [(e.clientX-b.left)*(W/b.width),(e.clientY-b.top)*(H/b.height)];};
 cv.onpointerdown=e=>{drag=true;px=e.clientX;};
 addEventListener('pointerup',()=>drag=false);
 cv.onpointermove=e=>{
  const [mx,my]=pos(e);
  if(drag){rot+=(e.clientX-px)*.008;px=e.clientX;}
  hover=null;
  countries.forEach(c=>{
   c.ips.forEach(x=>{if((mx-x.x)**2+(my-x.y)**2<(x.rad+5)**2)hover={e:x,c};});
   if(!hover&&Math.abs(mx-c.x)<c.rad*1.4&&Math.abs(my-c.y)<c.rad)hover={c};
  });
  cv.style.cursor=hover?'pointer':'grab';
 };
 cv.onclick=()=>{if(hover&&hover.e)ipinfo(hover.e.ip);};
}
load();
</script></body></html>
"""


class H(BaseHTTPRequestHandler):
    server_version = "sshlog/4.0"

    MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript",
            ".css": "text/css", ".json": "application/json",
            ".svg": "image/svg+xml", ".png": "image/png",
            ".ico": "image/x-icon", ".woff2": "font/woff2",
            ".woff": "font/woff", ".map": "application/json"}

    @staticmethod
    def serve_dist(path):
        """Serve React build from dist/; None if missing (legacy fallback)."""
        if path in ("/", "/ssh", "/index.html"):
            path = "/index.html"
        rel = path.lstrip("/").split("?")[0]
        if rel == "ssh" or rel.startswith("ssh/"):
            # Tolerate an unstripped /ssh prefix (proxy misconfig safety).
            rel = rel[3:].lstrip("/")
        if ".." in rel or rel.startswith("api/"):
            return None
        full = os.path.join(DIST, rel)
        if os.path.isfile(full):
            with open(full, "rb") as f:
                body = f.read()
            ext = os.path.splitext(full)[1].lower()
            return body, H.MIME.get(ext, "application/octet-stream")
        index = os.path.join(DIST, "index.html")
        if os.path.isfile(index):
            with open(index, "rb") as f:
                return f.read(), "text/html; charset=utf-8"
        return None

    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/healthz":
            return self._send(b"ok", "text/plain")
        if u.path == "/api/summary":
            try:
                host = (q.get("host", [""])[0] or "")[:64] or None
                return self._send(json.dumps(summary(host)), "application/json")
            except Exception as e:
                return self._send(json.dumps({"error": type(e).__name__}),
                                   "application/json", 500)
        if u.path == "/api/hosts":
            return self._send(json.dumps(list_hosts()), "application/json")
        if u.path == "/api/ipinfo":
            ip = (q.get("ip", [""])[0] or "")[:45]
            if not ip:
                return self._send('{"error":"missing ip"}', "application/json", 400)
            host = (q.get("host", [""])[0] or "")[:64] or None
            d = ip_detail(ip)
            d["flag"] = flag(d.get("cc", ""))
            d["history"] = ip_history(ip, host=host)
            return self._send(json.dumps(d), "application/json")
        if u.path == "/api/tail":
            filt = (q.get("q", [""])[0] or "")[:64].lower()
            try:
                n = max(10, min(2000, int(q.get("n", ["200"])[0])))
            except ValueError:
                n = 200
            host = (q.get("host", [""])[0] or "")[:64] or None
            lines = read_lines(host)
            out = [ln for ln in lines if filt in ln.lower()]
            return self._send("".join(out[-n:]), "text/plain")
        # React SPA (dist/) when built, else legacy single-file page.
        hit = self.serve_dist(u.path)
        if hit is not None:
            body, ctype = hit
            return self._send(body, ctype)
        if "PAGE" in globals():
            return self._send(PAGE)
        return self._send("not found", "text/plain", 404)

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/api/recon":
            ip = (q.get("ip", [""])[0] or "")[:45]
            if not is_public_ip(ip):
                return self._send('{"error":"not a public IP"}', "application/json", 400)
            force = q.get("force", [""])[0] == "1"
            return self._send(json.dumps(recon_status(ip, force=force)),
                               "application/json")
        if u.path == "/api/agent/push":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, OSError):
                return self._send('{"error":"bad json"}', "application/json", 400)
            host = str(body.get("host", ""))[:64]
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else ""
            if not host or not check_agent_token(host, token):
                return self._send('{"error":"unauthorized"}', "application/json", 401)
            lines = body.get("lines", [])
            if isinstance(lines, list) and lines:
                store_pushed_lines(host, [str(x)[:2000] for x in lines])
            return self._send(json.dumps({"ok": True, "host": host}), "application/json")
        return self._send("not found", "text/plain", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    import sys as _sys
    import threading

    if len(_sys.argv) >= 3 and _sys.argv[1] == "gentoken":
        # Mint a join token for an agent host: server.py gentoken <host-id>
        import secrets as _secrets
        host = "".join(c if (c.isalnum() or c in "-_") else "_" for c in _sys.argv[2])[:64]
        os.makedirs(DATA_DIR, exist_ok=True)
        agents = _agents()
        token = _secrets.token_urlsafe(32)
        agents[host] = token
        with open(AGENTS_FILE, "w") as f:
            json.dump(agents, f)
        try:
            os.chmod(AGENTS_FILE, 0o600)
        except OSError:
            pass
        print("host=%s" % host)
        print("token=%s" % token)
        print("central=%s (tailscale URL of this host)" % os.environ.get("CENTRAL_URL", "http://<this-host>:8079"))
        _sys.exit(0)

    def _geo_prime():
        """Keep geo cache warm for current attacker IPs (summary reads cache)."""
        try:
            lines = read_lines()
            mine = own_ips()
            per = Counter()
            for ln in lines[-20000:]:
                m = FAIL_RE.search(ln) or INVALID_RE.search(ln)
                if m and m.group(2) not in mine:
                    per[m.group(2)] += 1
            geo_lookup([ip for ip, _ in per.most_common(60)])
        except Exception:
            pass

    def _geo_loop():
        while True:
            _geo_prime()
            time.sleep(600)

    threading.Thread(target=_geo_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8079), H).serve_forever()
