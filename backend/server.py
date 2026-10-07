#!/usr/bin/env python3
"""SSH/auth security dashboard. Localhost only; SSO enforced by Traefik."""
import base64
import binascii
import hashlib
import html
import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode

LOG = os.environ.get("AUTH_LOG", "/var/log/auth.log")
DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
HOSTS_DIR = os.path.join(DATA_DIR, "hosts")
AGENTS_FILE = os.path.join(DATA_DIR, "agents.json")
ADMIN_FILE = os.path.join(DATA_DIR, "admin.json")
SETUP_TOKEN_FILE = os.path.join(DATA_DIR, "setup.token")
DB_PATH = os.path.join(DATA_DIR, "sentinel.db")
BANLIST_FILE = os.path.join(DATA_DIR, "banlist.txt")
HOST_ID = os.environ.get("HOST_ID", socket.gethostname().split(".")[0])
START_TS = time.time()
try:
    MAX_LINES_PER_HOST = max(1000, int(os.environ.get("MAX_LINES_PER_HOST", "60000")))
except ValueError:
    MAX_LINES_PER_HOST = 60000
# Privacy / redaction config.
# SHIP_FILTER: sshd-only (default) keeps sshd + pam_unix(sshd:session) lines,
#   drops sudo/CRON/systemd noise that leaks cwd/commands. Use "full" for debug.
# PRIVACY_MODE: balanced (default) shows attacker IPs fully, masks usernames
#   of normal Accepted logins (deploy -> d****y).
#   strict additionally masks the self-IP list.
#   Suspicious accepts are NEVER masked (compromise must stay visible).
#   The UI mask toggle hides the rest for screenshots.
# TRUSTED_IPS/TRUSTED_USERS: your admin IPs + service accounts. Any Accepted
#   login from an unknown IP/user, or after prior fails, is flagged suspicious.
SHIP_FILTER = os.environ.get("SHIP_FILTER", "sshd-only").strip().lower()
PRIVACY_MODE = os.environ.get("PRIVACY_MODE", "balanced").strip().lower()
if PRIVACY_MODE not in ("balanced", "strict", "off"):
    PRIVACY_MODE = "balanced"


def _csv_env(name):
    return {p.strip() for p in os.environ.get(name, "").split(",") if p.strip()}


TRUSTED_IPS = _csv_env("TRUSTED_IPS")
TRUSTED_USERS = _csv_env("TRUSTED_USERS")
import hmac as _hmac  # noqa: E402

# --- access control -----------------------------------------------------
# AUTH_MODE=local (default, fail-closed) | forward | oidc | none.
#   local:   HTTP Basic, single user from AUTH_USER + AUTH_PASS_HASH
#            (preferred; mint via `server.py genhash`) or AUTH_PASSWORD.
#            No credential configured -> deny-all with a setup hint.
#   forward: trust reverse-proxy OIDC/ForwardAuth identity headers
#            (Authentik via Traefik, same pattern as Dozzle dozzle-oidc):
#            X-Forwarded-User (or X-Forwarded-Email / Remote-User).
#            Optional AUTH_ALLOWED_USERS allowlist (csv, user or mail prefix).
#            Headers accepted only from AUTH_TRUSTED_PROXIES.
#   oidc:    built-in SSO: authorization-code flow against any OIDC
#            provider (Authentik, Keycloak, ...), RS256 ID tokens,
#            server-side sessions. Needs OIDC_* env (see below).
#   none:    explicit open mode for private tailnet/demo only. Never default.
AUTH_MODE = os.environ.get("AUTH_MODE", "local").strip().lower()
if AUTH_MODE not in ("local", "forward", "oidc", "none"):
    AUTH_MODE = "local"
AUTH_USER = os.environ.get("AUTH_USER", "admin").strip() or "admin"
_AUTH_USER_ENV = os.environ.get("AUTH_USER", "").strip()
AUTH_PASS_HASH = os.environ.get("AUTH_PASS_HASH", "").strip()
_AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "")
AUTH_ALLOWED_USERS = {p.strip() for p in os.environ.get("AUTH_ALLOWED_USERS", "").split(",") if p.strip()}
FWD_USER_HEADERS = ("X-Forwarded-User", "X-Forwarded-Email", "Remote-User",
                    "Cf-Access-Authenticated-User-Email", "X-Auth-Request-User",
                    "X-authentik-username", "X-authentik-email")
# Networks allowed to present SSO identity headers (spoof-safe ForwardAuth).
# Defaults cover loopback + RFC1918 (docker/traefik) + Tailscale CGNAT.
_TRUSTED_PROXIES_RAW = os.environ.get(
    "AUTH_TRUSTED_PROXIES",
    "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10")


def _trusted_proxy_nets():
    nets = []
    for part in _TRUSTED_PROXIES_RAW.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass
    return nets


_TRUSTED_PROXY_NETS = _trusted_proxy_nets()


def _via_trusted_proxy(addr):
    if not _TRUSTED_PROXY_NETS:
        return False
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    return any(ip in n for n in _TRUSTED_PROXY_NETS)


def _read_admin_file():
    try:
        with open(ADMIN_FILE) as f:
            d = json.load(f)
        if isinstance(d, dict) and d.get("user") and d.get("pass_hash"):
            return d
    except (OSError, ValueError):
        pass
    return {}


def _effective_local_user():
    if _AUTH_USER_ENV:
        return _AUTH_USER_ENV
    f = _read_admin_file()
    return f.get("user", "admin")


def _local_configured():
    if AUTH_PASS_HASH or _AUTH_PASSWORD:
        return True
    f = _read_admin_file()
    return bool(f.get("user") and f.get("pass_hash"))


def _setup_token():
    env_tok = os.environ.get("ADMIN_SETUP_TOKEN", "").strip()
    if env_tok:
        return env_tok, "env"
    try:
        with open(SETUP_TOKEN_FILE) as f:
            t = f.read().strip()
        if t:
            return t, "file"
    except OSError:
        pass
    return "", "none"


def _ensure_setup_token():
    if _local_configured():
        return ""
    if os.environ.get("ADMIN_SETUP_TOKEN", "").strip():
        return os.environ.get("ADMIN_SETUP_TOKEN", "").strip()
    try:
        with open(SETUP_TOKEN_FILE) as f:
            t = f.read().strip()
        if t:
            return t
    except OSError:
        pass
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        import secrets as _sec
        t = _sec.token_urlsafe(24)
        with open(SETUP_TOKEN_FILE, "w") as f:
            f.write(t + "\n")
        try:
            os.chmod(SETUP_TOKEN_FILE, 0o600)
        except OSError:
            pass
        return t
    except OSError:
        return ""


# --- built-in OIDC (AUTH_MODE=oidc) --------------------------------------
# Authorization-code flow, stdlib only. Provider needs a confidential client
# with redirect URI <public-URL>/oidc/callback and RS256 signatures
# (Authentik default). Sessions live server-side; the cookie is a random
# token, HttpOnly + SameSite=Lax (+ Secure when OIDC_COOKIE_SECURE=1).
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URL = os.environ.get("OIDC_REDIRECT_URL", "").strip()
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid email profile").strip() or "openid email profile"
try:
    OIDC_SESSION_TTL = max(300, int(os.environ.get("OIDC_SESSION_TTL", "43200")))
except ValueError:
    OIDC_SESSION_TTL = 43200
OIDC_COOKIE_SECURE = os.environ.get("OIDC_COOKIE_SECURE", "").strip().lower() in ("1", "yes", "true", "on")
_oidc_conf = {"ts": 0.0, "data": {}}
_oidc_jwks = {"ts": 0.0, "keys": {}}
_oidc_states = {}
_oidc_sessions = {}


def _b64url_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _oidc_configured():
    return bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_REDIRECT_URL)


def _oidc_discovery():
    if _oidc_conf["data"] and time.time() - _oidc_conf["ts"] < 3600:
        return _oidc_conf["data"]
    req = urllib.request.Request(
        OIDC_ISSUER + "/.well-known/openid-configuration",
        headers={"User-Agent": "ssh-sentinel-oidc/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        conf = json.load(r)
    for k in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if not conf.get(k):
            raise ValueError("discovery misses " + k)
    _oidc_conf.update({"ts": time.time(), "data": conf})
    return conf


def _oidc_keys():
    if _oidc_jwks["keys"] and time.time() - _oidc_jwks["ts"] < 3600:
        return _oidc_jwks["keys"]
    conf = _oidc_discovery()
    req = urllib.request.Request(
        conf["jwks_uri"],
        headers={"User-Agent": "ssh-sentinel-oidc/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        jwks = json.load(r)
    keys = {}
    for j in jwks.get("keys", []):
        if j.get("kty") != "RSA" or j.get("use", "sig") != "sig":
            continue
        if not j.get("kid") or not j.get("n") or not j.get("e"):
            continue
        keys[j["kid"]] = (int.from_bytes(_b64url_dec(j["n"]), "big"),
                           int.from_bytes(_b64url_dec(j["e"]), "big"))
    if not keys:
        raise ValueError("no RSA signing keys in JWKS")
    _oidc_jwks.update({"ts": time.time(), "keys": keys})
    return keys


_SHA256_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _verify_rs256(msg, sig, n, e):
    """Verify an RS256 signature with pow() + PKCS#1 v1.5 unpad. No deps."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    try:
        em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    except (ValueError, OverflowError):
        return False
    if len(em) < 2 or em[0] != 0 or em[1] != 1:
        return False
    try:
        sep = em.index(b"\x00", 2)
    except ValueError:
        return False
    if sep < 10 or any(b != 0xFF for b in em[2:sep]):
        return False
    rest = em[sep + 1:]
    if len(rest) != len(_SHA256_DER_PREFIX) + 32:
        return False
    if rest[:len(_SHA256_DER_PREFIX)] != _SHA256_DER_PREFIX:
        return False
    return _hmac.compare_digest(rest[len(_SHA256_DER_PREFIX):],
                                 hashlib.sha256(msg).digest())


def _verify_id_token(token, nonce):
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError:
        raise ValueError("malformed id_token")
    try:
        header = json.loads(_b64url_dec(h_b64))
        claims = json.loads(_b64url_dec(p_b64))
        sig = _b64url_dec(s_b64)
    except (ValueError, binascii.Error):
        raise ValueError("malformed id_token encoding")
    if header.get("alg") != "RS256":
        raise ValueError("need RS256, provider sent " + str(header.get("alg")))
    keys = _oidc_keys()
    kid = header.get("kid", "")
    key = keys.get(kid) or (next(iter(keys.values())) if len(keys) == 1 else None)
    if not key:
        raise ValueError("unknown signing key")
    if not _verify_rs256(("%s.%s" % (h_b64, p_b64)).encode(), sig, key[0], key[1]):
        raise ValueError("bad token signature")
    now = time.time()
    if claims.get("exp", 0) < now - 30:
        raise ValueError("token expired")
    if claims.get("iat", 0) > now + 300:
        raise ValueError("token issued in the future")
    conf = _oidc_discovery()
    if claims.get("iss", "").rstrip("/") != conf["issuer"].rstrip("/"):
        raise ValueError("wrong issuer")
    aud = claims.get("aud")
    if OIDC_CLIENT_ID not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError("wrong audience")
    if nonce and claims.get("nonce") != nonce:
        raise ValueError("wrong nonce")
    return claims


def _cookies(header):
    out = {}
    for part in (header or "").split(";"):
        k, _, v = part.partition("=")
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


def _cookie_str(name, value, max_age=None, clear=False):
    parts = ["%s=%s" % (name, value), "Path=/", "HttpOnly", "SameSite=Lax"]
    if OIDC_COOKIE_SECURE:
        parts.append("Secure")
    if clear:
        parts.append("Max-Age=0")
    elif max_age:
        parts.append("Max-Age=%d" % max_age)
    return "; ".join(parts)


def _oidc_session_user(cookie_header):
    tok = _cookies(cookie_header).get("ssh_session", "")
    s = _oidc_sessions.get(tok)
    if not s:
        return ""
    if s["exp"] < time.time():
        _oidc_sessions.pop(tok, None)
        return ""
    return s["user"]


def _oidc_prune():
    now = time.time()
    for st, v in list(_oidc_states.items()):
        if now - v["ts"] > 600:
            _oidc_states.pop(st, None)
    for tok, v in list(_oidc_sessions.items()):
        if v["exp"] < now:
            _oidc_sessions.pop(tok, None)
# Public abusers feed: per-client RPM budget (in-memory, per process).
try:
    ABUSERS_RPM = max(1, int(os.environ.get("ABUSERS_RPM", "60")))
except ValueError:
    ABUSERS_RPM = 60
ABUSERS_TTL = 60
# ABUSERS_PUBLIC=1 exposes the safe-fields feed + leaderboard without login.
# Data is attacker-only by construction (no logins, hostnames, private IPs).
ABUSERS_PUBLIC = os.environ.get("ABUSERS_PUBLIC", "").strip().lower() in ("1", "yes", "true", "on")
# Admin whitelist: these IPs never appear in attacker lists (abusers, top,
# map). Comma-separated. The owner asks the admin to add them here.
WHITELIST_IPS = _csv_env("WHITELIST_IPS")
# Public-list quality bar: multi-attempt attackers only. A forgetful user
# with a few fails followed by a correct login is never listed publicly.
try:
    ABUSERS_MIN_HITS = max(2, int(os.environ.get("ABUSERS_MIN_HITS", "5")))
except ValueError:
    ABUSERS_MIN_HITS = 5
try:
    ABUSERS_MIN_SCORE = max(0, min(100, int(os.environ.get("ABUSERS_MIN_SCORE", "25"))))
except ValueError:
    ABUSERS_MIN_SCORE = 25
# Optional AbuseIPDB enrichment (abuse confidence 0-100 feeds the score).
# Get a key at abuseipdb.com (free tier is enough). Empty = skipped.
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "").strip()
ABUSE_TTL = 24 * 3600


def abuse_score(ip):
    """AbuseIPDB confidence 0-100, cached 24h. 0 when keyless/offline."""
    if not ABUSEIPDB_KEY:
        return 0
    key = "abuse:" + ip
    ent = _cache.get(key, {})
    if ent and time.time() - ent.get("ts", 0) < ABUSE_TTL:
        return ent.get("score", 0)
    score = 0
    try:
        req = urllib.request.Request(
            "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json",
                     "User-Agent": "ssh-sentinel/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r).get("data", {})
        score = max(0, min(100, int(data.get("abuseConfidenceScore", 0))))
    except Exception:
        score = 0
    _cache[key] = {"score": score, "ts": time.time()}
    return score


def risk_of(hits, users_n, last_ms, accepted, external=0, velocity=0, prior_ban=False):
    """Risk 0-100 with reasons. Accepted logins push far below the bar."""
    import math as _math
    reasons = []
    score = min(40, int(12 * _math.log10(1 + hits)))
    reasons.append("%d attempts" % hits)
    ub = min(30, 8 * users_n)
    score += ub
    if users_n > 1:
        reasons.append("%d users tried" % users_n)
    now_ms = int(time.time() * 1000)
    if last_ms and now_ms - last_ms < 3600000:
        score += 15
        reasons.append("active this hour")
    elif last_ms and now_ms - last_ms < 86400000:
        score += 10
        reasons.append("active today")
    if velocity and velocity >= 5:
        vb = min(20, int(velocity // 2))
        score += vb
        reasons.append("fast hammer: %d/h" % int(velocity))
    if prior_ban:
        score += 15
        reasons.append("banned before")
    if accepted:
        score -= 100
        reasons.append("has a successful login (likely the owner)")
    if external:
        score += min(25, external // 2)
        reasons.append("abuse reports: %d/100" % external)
    score = max(0, min(100, score))
    band = "low" if score < 30 else ("medium" if score < 60 else ("high" if score < 80 else "critical"))
    return score, band, reasons


# --- bans, risk store, reports (issue #19) --------------------------------
# All stdlib. SQLite file lives in DATA_DIR. Logs stay source of truth.
def _bool_env(name, default=False):
    v = os.environ.get(name, "").strip().lower()
    if not v:
        return default
    return v in ("1", "yes", "true", "on")


def _int_env(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(os.environ.get(name, str(default)).strip() or default)))
    except ValueError:
        return default


BAN_ENABLED = _bool_env("BAN_ENABLED", False)
BAN_JAIL = os.environ.get("BAN_JAIL", "sshd").strip() or "sshd"
BAN_TIME = _int_env("BAN_TIME", 86400, 300, 30 * 86400)
BAN_AUTO = _bool_env("BAN_AUTO", False)
BAN_THRESHOLD = _int_env("BAN_THRESHOLD", 20, 3, 10000)
BAN_WINDOW = _int_env("BAN_WINDOW", 600, 60, 7 * 86400)
BAN_AUTO_TIME = _int_env("BAN_AUTO_TIME", 86400, 300, 30 * 86400)
REPORT_ENABLED = _bool_env("REPORT_ENABLED", False)
REPORT_PROVIDER = os.environ.get("REPORT_PROVIDER", "abuseipdb").strip().lower() or "abuseipdb"
REPORT_THROTTLE_DAYS = _int_env("REPORT_THROTTLE_DAYS", 7, 1, 90)
REPORT_MIN_RISK = _int_env("REPORT_MIN_RISK", 60, 0, 100)
REPORT_MIN_HITS = _int_env("REPORT_MIN_HITS", 20, 2, 100000)
ABUSE_WEBHOOK_URL = os.environ.get("ABUSE_WEBHOOK_URL", "").rstrip("/")
ABUSE_WEBHOOK_TOKEN = os.environ.get("ABUSE_WEBHOOK_TOKEN", "")
# --- login + spike alerts (issue #25) --------------------------------------
# ALERT_WEBHOOK_URL: POST JSON {event, ip, user, hits, ...} on suspicious
# Accepted login (ALERT_ON_SUCCESS=1) or brute-force spike (> threshold
# fails in window). Falls back to ABUSE_WEBHOOK_URL when unset. Dedupe per
# key for ALERT_DEDUPE_S. Stdlib only, best-effort, never blocks the API.
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "").rstrip("/") or ABUSE_WEBHOOK_URL
ALERT_WEBHOOK_TOKEN = os.environ.get("ALERT_WEBHOOK_TOKEN", "") or ABUSE_WEBHOOK_TOKEN
ALERT_ON_SUCCESS = _bool_env("ALERT_ON_SUCCESS", True)
ALERT_SPIKE_THRESHOLD = _int_env("ALERT_SPIKE_THRESHOLD", 20, 2, 100000)
ALERT_SPIKE_WINDOW_S = _int_env("ALERT_SPIKE_WINDOW_S", 300, 60, 86400)
ALERT_DEDUPE_S = _int_env("ALERT_DEDUPE_S", 3600, 60, 7 * 86400)
_alert_sent = {}


def _valid_ip(s):
    try:
        a = ipaddress.ip_address(str(s).strip())
        return str(a)
    except ValueError:
        return ""


def db():
    os.makedirs(DATA_DIR, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.execute("PRAGMA journal_mode=WAL")
    return c


_DB_READY = False


def _ensure_db():
    global _DB_READY
    if _DB_READY:
        return
    try:
        db_init()
    except Exception:
        pass
    _DB_READY = True


def db_init():
    c = db()
    try:
        c.execute("CREATE TABLE IF NOT EXISTS ip_stats"
                  "(ip TEXT PRIMARY KEY, hits INTEGER, users_json TEXT,"
                  " first REAL, last REAL, risk INTEGER, band TEXT,"
                  " reasons_json TEXT, updated REAL)")
        c.execute("CREATE TABLE IF NOT EXISTS bans"
                  "(ip TEXT PRIMARY KEY, jail TEXT, reason TEXT, source TEXT,"
                  " created REAL, expires REAL, active INTEGER, fail2ban_ok INTEGER)")
        c.execute("CREATE TABLE IF NOT EXISTS reports"
                  "(ip TEXT, provider TEXT, ts REAL, status TEXT, detail TEXT,"
                  " PRIMARY KEY (ip, provider))")
        c.execute("CREATE TABLE IF NOT EXISTS activity"
                  "(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT,"
                  " action TEXT, ip TEXT, detail TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT)")
        c.commit()
    finally:
        c.close()


def activity_log(actor, action, ip="", detail=""):
    try:
        c = db()
        try:
            c.execute("INSERT INTO activity(ts, actor, action, ip, detail)"
                      " VALUES(?,?,?,?,?)",
                      (time.time(), str(actor)[:80], str(action)[:40],
                       str(ip)[:45], str(detail)[:500]))
            c.execute("DELETE FROM activity WHERE id NOT IN"
                      " (SELECT id FROM activity ORDER BY id DESC LIMIT 2000)")
            c.commit()
        finally:
            c.close()
    except Exception:
        pass


def activity_list(limit=200):
    try:
        c = db()
        try:
            rows = c.execute("SELECT ts, actor, action, ip, detail FROM activity"
                             " ORDER BY id DESC LIMIT ?",
                             (max(1, min(500, int(limit))),)).fetchall()
        finally:
            c.close()
        return [{"ts": int(t * 1000), "actor": a, "action": ac,
                 "ip": ip, "detail": d} for t, a, ac, ip, d in rows]
    except Exception:
        return []


def _write_banlist(active_ips):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(BANLIST_FILE, "w") as f:
            for ip in sorted(set(active_ips)):
                f.write(ip + "\n")
        try:
            os.chmod(BANLIST_FILE, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def ban_list_active():
    try:
        now = time.time()
        c = db()
        try:
            rows = c.execute("SELECT ip, jail, reason, source, created, expires,"
                             " fail2ban_ok FROM bans WHERE active=1").fetchall()
        finally:
            c.close()
        out = []
        for ip, jail, reason, source, created, expires, ok in rows:
            if expires and expires < now:
                continue
            out.append({"ip": ip, "jail": jail, "reason": reason,
                        "source": source, "created": int(created * 1000),
                        "expires": int(expires * 1000) if expires else None,
                        "fail2ban_ok": bool(ok)})
        return out
    except Exception:
        return []


def _fail2ban(cmd, jail, ip):
    try:
        r = subprocess.run(["fail2ban-client", "set", jail, cmd, ip],
                           timeout=10, capture_output=True, text=True)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def ban_add(ip, reason="", source="manual", actor="admin", ttl=None):
    ip = _valid_ip(ip)
    if not ip:
        return {"ok": False, "error": "bad ip"}
    try:
        a = ipaddress.ip_address(ip)
        if not (a.is_global and not a.is_reserved):
            return {"ok": False, "error": "not a public IP"}
    except ValueError:
        return {"ok": False, "error": "bad ip"}
    if ip in WHITELIST_IPS or ip in own_ips():
        return {"ok": False, "error": "IP is whitelisted or self"}
    ttl_s = BAN_TIME if ttl is None else max(300, min(30 * 86400, int(ttl)))
    now = time.time()
    ok = _fail2ban("banip", BAN_JAIL, ip) if BAN_ENABLED else False
    try:
        c = db()
        try:
            c.execute("INSERT OR REPLACE INTO bans"
                      "(ip, jail, reason, source, created, expires, active, fail2ban_ok)"
                      " VALUES(?,?,?,?,?,?,1,?)",
                      (ip, BAN_JAIL, str(reason)[:200], str(source)[:20],
                       now, now + ttl_s, 1 if ok else 0))
            c.commit()
        finally:
            c.close()
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}
    _write_banlist([b["ip"] for b in ban_list_active()])
    activity_log(actor, "ban", ip, "%s via %s f2b=%s" % (source, BAN_JAIL, ok))
    return {"ok": True, "ip": ip, "fail2ban_ok": ok,
            "expires": int((now + ttl_s) * 1000)}


def ban_remove(ip, actor="admin"):
    ip = _valid_ip(ip)
    if not ip:
        return {"ok": False, "error": "bad ip"}
    ok = _fail2ban("unbanip", BAN_JAIL, ip) if BAN_ENABLED else False
    try:
        c = db()
        try:
            c.execute("UPDATE bans SET active=0 WHERE ip=?", (ip,))
            c.commit()
        finally:
            c.close()
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}
    _write_banlist([b["ip"] for b in ban_list_active()])
    activity_log(actor, "unban", ip, "via %s f2b=%s" % (BAN_JAIL, ok))
    return {"ok": True, "ip": ip}


def ban_state(ip):
    try:
        c = db()
        try:
            r = c.execute("SELECT source, created, expires, active FROM bans"
                          " WHERE ip=?", (ip,)).fetchone()
        finally:
            c.close()
        if not r or not r[3]:
            return {"banned": False}
        if r[2] and r[2] < time.time():
            return {"banned": False}
        return {"banned": True, "source": r[0],
                "created": int(r[1] * 1000), "expires": int(r[2] * 1000)}
    except Exception:
        return {"banned": False}


def prior_ban_flag(ip):
    try:
        c = db()
        try:
            r = c.execute("SELECT 1 FROM bans WHERE ip=? LIMIT 1", (ip,)).fetchone()
        finally:
            c.close()
        return bool(r)
    except Exception:
        return False


def report_state(ip):
    try:
        c = db()
        try:
            rows = c.execute("SELECT provider, ts, status FROM reports"
                             " WHERE ip=?", (ip,)).fetchall()
        finally:
            c.close()
        return [{"provider": p, "ts": int(t * 1000), "status": s}
                for p, t, s in rows]
    except Exception:
        return []


def _report_due(ip, provider):
    try:
        c = db()
        try:
            r = c.execute("SELECT ts FROM reports WHERE ip=? AND provider=?",
                          (ip, provider)).fetchone()
        finally:
            c.close()
        if not r:
            return True
        return (time.time() - r[0]) > REPORT_THROTTLE_DAYS * 86400
    except Exception:
        return True


def _report_record(ip, provider, status, detail=""):
    try:
        c = db()
        try:
            c.execute("INSERT OR REPLACE INTO reports(ip, provider, ts, status, detail)"
                      " VALUES(?,?,?,?,?)",
                      (ip, provider, time.time(), str(status)[:40],
                       str(detail)[:500]))
            c.commit()
        finally:
            c.close()
    except Exception:
        pass


def _abuseipdb_report(ip, hits, risk):
    if not ABUSEIPDB_KEY:
        return False, "no key"
    try:
        fields = {"ipAddress": ip, "categories": "22",
                  "comment": "SSH brute force: %d fails, risk %d (ssh-sentinel)" % (hits, risk)}
        data = urlencode(fields).encode()
        req = urllib.request.Request(
            "https://api.abuseipdb.com/api/v2/report", data=data,
            headers={"Key": ABUSEIPDB_KEY,
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json",
                     "User-Agent": "ssh-sentinel/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            payload = json.load(r)
        err = ""
        try:
            err = str(payload.get("errors", ""))[:200]
        except Exception:
            err = ""
        if err:
            return False, err
        return True, "reported"
    except Exception as e:
        return False, type(e).__name__


def _webhook_report(ip, hits, risk, band):
    if not ABUSE_WEBHOOK_URL:
        return False, "no webhook"
    try:
        body = {"ip": ip, "hits": hits, "risk": risk, "band": band,
                "categories": ["ssh-brute-force"], "source": "ssh-sentinel"}
        headers = {"Content-Type": "application/json",
                   "User-Agent": "ssh-sentinel-report/1.0"}
        if ABUSE_WEBHOOK_TOKEN:
            headers["Authorization"] = "Bearer " + ABUSE_WEBHOOK_TOKEN
        req = urllib.request.Request(ABUSE_WEBHOOK_URL, data=json.dumps(body).encode(),
                                     headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read(4096)
        return True, "reported"
    except Exception as e:
        return False, type(e).__name__


def report_ip(ip, hits, risk, band, actor="system"):
    """Report one IP to enabled providers. Throttled. Safe payload only."""
    ip = _valid_ip(ip)
    if not ip:
        return {"ok": False, "error": "bad ip"}
    if not REPORT_ENABLED:
        return {"ok": False, "error": "reports off"}
    if hits < REPORT_MIN_HITS or risk < REPORT_MIN_RISK:
        return {"ok": False, "error": "below bar"}
    providers = []
    if REPORT_PROVIDER in ("abuseipdb", "all"):
        providers.append("abuseipdb")
    if REPORT_PROVIDER in ("webhook", "all"):
        providers.append("webhook")
    out = {}
    for p in providers:
        if not _report_due(ip, p):
            out[p] = "throttled"
            continue
        if p == "abuseipdb":
            ok, msg = _abuseipdb_report(ip, hits, risk)
        else:
            ok, msg = _webhook_report(ip, hits, risk, band)
        _report_record(ip, p, "sent" if ok else "error", msg)
        activity_log(actor, "report", ip, "%s: %s" % (p, msg))
        out[p] = msg
    return {"ok": True, "ip": ip, "results": out}


def admin_status():
    tok, _ = _setup_token()
    return {"setup_needed": not _local_configured(),
            "setup_token_configured": bool(tok),
            "ban_enabled": BAN_ENABLED, "ban_auto": BAN_AUTO,
            "ban_jail": BAN_JAIL, "ban_threshold": BAN_THRESHOLD,
            "ban_window": BAN_WINDOW,
            "report_enabled": REPORT_ENABLED, "report_provider": REPORT_PROVIDER,
            "report_throttle_days": REPORT_THROTTLE_DAYS,
            "alert_configured": bool(ALERT_WEBHOOK_URL),
            "alert_on_success": ALERT_ON_SUCCESS,
            "alert_spike_threshold": ALERT_SPIKE_THRESHOLD,
            "alert_spike_window_s": ALERT_SPIKE_WINDOW_S,
            "auth_mode": AUTH_MODE, "version": os.environ.get("APP_VERSION", "dev")}


def _alert_send(event, payload):
    """POST one alert. Dedupe per key. Returns True if sent."""
    if not ALERT_WEBHOOK_URL:
        return False
    key = event + ":" + str(payload.get("ip", "")) + ":" + str(payload.get("user", ""))
    if time.time() - _alert_sent.get(key, 0) < ALERT_DEDUPE_S:
        return False
    _alert_sent[key] = time.time()
    try:
        body = {"event": event, "source": "ssh-sentinel",
                "ts": int(time.time() * 1000)}
        body.update(payload)
        headers = {"Content-Type": "application/json",
                   "User-Agent": "ssh-sentinel-alert/1.0"}
        if ALERT_WEBHOOK_TOKEN:
            headers["Authorization"] = "Bearer " + ALERT_WEBHOOK_TOKEN
        req = urllib.request.Request(ALERT_WEBHOOK_URL, data=json.dumps(body).encode(),
                                     headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read(4096)
        activity_log("system", "alert", str(payload.get("ip", "")), event)
        return True
    except Exception:
        _alert_sent.pop(key, None)
        return False


def maybe_alert(summ):
    """Fire success + spike alerts from a computed summary. Best-effort."""
    if not ALERT_WEBHOOK_URL:
        return
    try:
        if ALERT_ON_SUCCESS:
            for e in (summ.get("logins") or [])[-10:]:
                if e.get("suspicious"):
                    _alert_send("login.suspicious",
                                {"ip": e.get("ip"), "user": e.get("user"),
                                 "reason": e.get("reason")})
        now_ms = summ.get("now", int(time.time() * 1000))
        win_start = now_ms - ALERT_SPIKE_WINDOW_S * 1000
        recent = sum(f for (h, f, _o) in (summ.get("timeline") or []) if h >= win_start)
        if recent >= ALERT_SPIKE_THRESHOLD:
            _alert_send("spike.bruteforce", {"hits": recent,
                                             "window_s": ALERT_SPIKE_WINDOW_S})
    except Exception:
        pass


try:
    _ensure_db()
except Exception:
    pass


def _sync_ip_stats(entries):
    try:
        c = db()
        try:
            now = time.time()
            for e in entries[:200]:
                c.execute("INSERT OR REPLACE INTO ip_stats"
                          "(ip, hits, users_json, first, last, risk, band,"
                          " reasons_json, updated) VALUES(?,?,?,?,?,?,?,?,?)",
                          (e["ip"], e["hits"],
                           json.dumps(e.get("attempted_users", [])[:10]),
                           (e.get("first") or 0) / 1000.0 if e.get("first") else 0,
                           (e.get("last") or 0) / 1000.0 if e.get("last") else 0,
                           e.get("risk", 0), e.get("band", ""),
                           json.dumps(e.get("reasons", [])), now))
            c.commit()
        finally:
            c.close()
    except Exception:
        pass


def _auto_ban_scan():
    if not BAN_AUTO:
        return 0
    try:
        lines = read_lines("all")[-20000:]
    except Exception:
        return 0
    now = datetime.now()
    cutoff = time.time() - BAN_WINDOW
    per_ip = Counter()
    for ln in lines:
        m = FAIL_RE.search(ln) or INVALID_RE.search(ln)
        ip = None
        if m:
            ip = m.group(2)
        else:
            m2 = CLOSED_RE.search(ln) or DISC_RE.search(ln)
            if m2 and is_public_ip(m2.group(1)):
                ip = m2.group(1)
        if not ip:
            continue
        ts = parse_ts(ln, now)
        ets = ts.timestamp() if ts else time.time()
        if ets < cutoff:
            continue
        per_ip[ip] += 1
    try:
        mine = own_ips()
    except Exception:
        mine = set()
    accepted = set()
    try:
        for ln in lines[-5000:]:
            am = ACCEPT_RE.search(ln)
            if am:
                accepted.add(am.group(2))
    except Exception:
        pass
    active = {b["ip"] for b in ban_list_active()}
    n = 0
    for ip, hits in per_ip.most_common(100):
        if hits < BAN_THRESHOLD:
            continue
        if ip in active or ip in mine or ip in WHITELIST_IPS:
            continue
        if not is_public_ip(ip) or ip in accepted:
            continue
        velocity = hits * 3600.0 / max(60, BAN_WINDOW)
        ext = abuse_score(ip) if ABUSEIPDB_KEY else 0
        score, _band, _reasons = risk_of(hits, 3, int(time.time() * 1000),
                                         False, ext, velocity, prior_ban_flag(ip))
        if score < ABUSERS_MIN_SCORE:
            continue
        r = ban_add(ip, "auto: %d fails in %ds" % (hits, BAN_WINDOW),
                    "auto", "system", BAN_AUTO_TIME)
        if r.get("ok"):
            n += 1
    return n


def _auto_report_scan():
    if not REPORT_ENABLED:
        return 0
    try:
        entries = abusers("all")[:30]
    except Exception:
        return 0
    _sync_ip_stats(entries)
    n = 0
    for e in entries:
        if e.get("hits", 0) < REPORT_MIN_HITS or e.get("risk", 0) < REPORT_MIN_RISK:
            continue
        due = any(_report_due(e["ip"], p) for p in (
            ["abuseipdb"] if REPORT_PROVIDER == "abuseipdb" else
            ["webhook"] if REPORT_PROVIDER == "webhook" else ["abuseipdb", "webhook"]))
        if not due:
            continue
        r = report_ip(e["ip"], e["hits"], e["risk"], e.get("band", ""), "system")
        if r.get("ok"):
            n += 1
        if n >= 5:
            break
    return n


def _ops_loop():
    while True:
        try:
            _auto_ban_scan()
        except Exception:
            pass
        try:
            _auto_report_scan()
        except Exception:
            pass
        time.sleep(60)
# Optional in-repo TLS (TLS 1.3 only). Off unless both point at files.
# Preferred fleet path stays: Tailscale cert on central + https CENTRAL_URL.
TLS_CERT = os.environ.get("TLS_CERT", "").strip()
TLS_KEY = os.environ.get("TLS_KEY", "").strip()


def _parse_pass_hash(s):
    """Parse AUTH_PASS_HASH: pbkdf2-sha256$<iter>$<salt-hex>$<hash-hex>."""
    try:
        algo, it, salt, hh = s.split("$")
        if algo != "pbkdf2-sha256":
            return None
        return (int(it), bytes.fromhex(salt), bytes.fromhex(hh))
    except (ValueError, TypeError):
        return None


def _verify_local_password(pw):
    if AUTH_PASS_HASH:
        p = _parse_pass_hash(AUTH_PASS_HASH)
        if not p:
            return False
        it, salt, expect = p
        try:
            got = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it)
        except (ValueError, OverflowError):
            return False
        return _hmac.compare_digest(got, expect)
    if _AUTH_PASSWORD:
        return bool(pw) and _hmac.compare_digest(pw, _AUTH_PASSWORD)
    f = _read_admin_file()
    if f.get("pass_hash"):
        p = _parse_pass_hash(f["pass_hash"])
        if not p:
            return False
        it, salt, expect = p
        try:
            got = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it)
        except (ValueError, OverflowError):
            return False
        return _hmac.compare_digest(got, expect)
    return False


def _mint_pass_hash(pw):
    import secrets as _sec
    salt = _sec.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200000)
    return "pbkdf2-sha256$200000$%s$%s" % (salt.hex(), dk.hex())


def _repo_file(name):
    """Find a shipped repo file: /srv/<name> in the image, repo root in dev."""
    cands = [os.path.join("/srv", name),
             os.path.normpath(os.path.join(
                 os.path.dirname(os.path.abspath(__file__)), "..", name))]
    for p in cands:
        if os.path.isfile(p):
            return p
    return ""


def app_version():
    v = os.environ.get("APP_VERSION", "").strip()
    if v and v != "dev":
        return v
    p = _repo_file("VERSION")
    if p:
        try:
            with open(p) as f:
                v = f.read().strip()
            if v:
                return v
        except OSError:
            pass
    return v or "dev"


def version_info():
    """Open build info for the UI About dialog. No secrets."""
    log = ""
    p = _repo_file("CHANGELOG.md")
    if p:
        try:
            with open(p, errors="replace") as f:
                log = f.read(20480)
        except OSError:
            log = ""
    return {"version": app_version(),
            "commit": os.environ.get("GIT_COMMIT", "")[:12],
            "changelog": log}


def auth_status(user=None):
    login = {"none": "none", "forward": "forward", "oidc": "oidc"}.get(AUTH_MODE, "basic")
    return {"mode": AUTH_MODE, "login": login,
            "user": user or None,
            "safe": AUTH_MODE in ("local", "forward", "oidc"),
            "version": app_version(),
            "abusers_public": ABUSERS_PUBLIC,
            "setup_needed": AUTH_MODE == "local" and not _local_configured()}


def health():
    """Open liveness/readiness snapshot for uptime monitors. No secrets."""
    try:
        log_ok = os.access(LOG, os.R_OK)
        log_size = os.path.getsize(LOG) if log_ok else 0
    except OSError:
        log_ok, log_size = False, 0
    try:
        hosts = list_hosts()
    except Exception:
        hosts = []
    return {"status": "ok", "uptime_s": int(time.time() - START_TS),
            "version": app_version(),
            "mode": AUTH_MODE, "time": int(time.time() * 1000),
            "hosts": len(hosts),
            "hosts_online": sum(1 for h in hosts if h.get("online")),
            "geo_cached": sum(1 for k in _cache if k.startswith("geo:")),
            "log_ok": log_ok, "log_bytes": log_size,
            "data_ok": os.access(DATA_DIR, os.W_OK)}


def mask_user(u):
    """Mask an accepted username: deploy -> d****y."""
    if not u or len(u) <= 2:
        return "***"
    return u[0] + "****" + u[-1]


def mask_ip(ip):
    """Mask last octet/hextet for display: 1.2.3.4 -> 1.2.3.*."""
    try:
        if "." in ip:
            parts = ip.split(".")
            if len(parts) == 4:
                return ".".join(parts[:3]) + ".*"
        if ":" in ip:
            parts = ip.split(":")
            return ":".join(parts[:-1]) + ":*"
    except Exception:
        pass
    return "***"


def is_sshd_line(ln):
    """True for lines we keep in sshd-only mode (auth signal, no sudo leakage)."""
    if PRIVACY_MODE == "off" or SHIP_FILTER == "full":
        return True
    l = ln.lower()
    # Keep sshd core events + sshd session open/close. Drop sudo COMMAND/PWD,
    # CRON, systemd-logind, polkit, etc.
    if "sshd" in l:
        return True
    if "pam_unix(sshd" in l:
        return True
    return False


def sanitize_line(ln):
    """Redact command args / cwd if a non-sshd line slips through (full mode)."""
    if PRIVACY_MODE == "off":
        return ln
    # sudo leaks: TTY, PWD, COMMAND with args (may contain secrets).
    ln = re.sub(r"PWD=\S+", "PWD=<redacted>", ln)
    ln = re.sub(r"TTY=\S+", "TTY=<redacted>", ln)
    # Keep binary name, redact args: COMMAND=/usr/bin/x args... -> COMMAND=/usr/bin/x <args-redacted>
    def _cmd(m):
        return m.group(1) + " <args-redacted>"
    ln = re.sub(r"(COMMAND=\S+).*?(;|$)", _cmd, ln)
    return ln


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
    # Defense in depth: re-apply allowlist server-side (old agents may send full logs).
    kept = []
    for raw in lines[:5000]:
        s = str(raw)[:2000]
        if not is_sshd_line(s):
            continue
        kept.append(sanitize_line(s))
    # If filtering removed everything but input was non-empty, keep nothing
    # (prevents sudo-only pushes from creating noise). Fall through to meta update.
    with open(p, "a") as f:
        for ln in kept:
            f.write((ln if ln.endswith("\n") else ln + "\n"))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
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
SPIDER = os.environ.get("SPIDERFOOT_URL", "http://spiderfoot:5001").rstrip("/")
RECON_MODULES = os.environ.get("RECON_MODULES", "sfp_dnsresolve,sfp_whois,sfp_ipapico,sfp_abusech")
# Recon providers: spiderfoot (default) | webhook (your own intel hook) | none.
# Webhook contract: POST {"ip": "1.2.3.4"} -> {"findings": [{"type": "...",
# "data": "...", "module": "..."}]} (keys type/data/module also accept
# eventType/finding|value|info and source/provider aliases). Optional bearer
# via RECON_WEBHOOK_TOKEN.
RECON_PROVIDER = os.environ.get("RECON_PROVIDER", "spiderfoot").strip().lower()
if RECON_PROVIDER not in ("spiderfoot", "webhook", "none"):
    RECON_PROVIDER = "spiderfoot"
RECON_WEBHOOK_URL = os.environ.get("RECON_WEBHOOK_URL", "").rstrip("/")
RECON_WEBHOOK_TOKEN = os.environ.get("RECON_WEBHOOK_TOKEN", "")
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


def _recon_webhook(key, ip, force=False):
    """POST the IP to a generic intel hook, normalize findings, cache 7d."""
    if not RECON_WEBHOOK_URL:
        return {"state": "error", "error": "RECON_WEBHOOK_URL is empty"}
    headers = {"Content-Type": "application/json",
               "User-Agent": "ssh-sentinel-recon/1.0"}
    if RECON_WEBHOOK_TOKEN:
        headers["Authorization"] = "Bearer " + RECON_WEBHOOK_TOKEN
    try:
        req = urllib.request.Request(
            RECON_WEBHOOK_URL, data=json.dumps({"ip": ip}).encode(),
            headers=headers)
        with urllib.request.urlopen(req, timeout=25) as r:
            payload = json.load(r)
    except Exception as e:
        return {"state": "error", "error": "webhook failed: " + type(e).__name__}
    items = []
    if isinstance(payload, dict):
        items = payload.get("findings") or payload.get("results") or []
    elif isinstance(payload, list):
        items = payload
    seen, out = set(), []
    for f in items:
        if not isinstance(f, dict):
            continue
        typ = str(f.get("type") or f.get("eventType") or "FINDING")
        data = str(f.get("data") or f.get("finding") or f.get("value")
                   or f.get("info") or "").strip()
        mod = str(f.get("module") or f.get("source") or f.get("provider")
                  or "webhook")
        if not data or (typ, data) in seen:
            continue
        seen.add((typ, data))
        out.append({"type": typ[:64], "data": data[:300], "module": mod[:64]})
        if len(out) >= 60:
            break
    d = {"state": "done", "scan": "webhook", "status": "FINISHED", "done": True,
         "ts": time.time(), "count": len(out), "results": out}
    _cache[key] = d
    save_cache()
    return d


def recon_status(ip, force=False):
    """Auto-fire recon for ip via RECON_PROVIDER, cache results, report state.

    Returns dict(state= cached|started|running|done|error, ...). Callers
    poll until state == done; results render inline in the intel modal.
    """
    key = "recon:" + ip
    ent = _cache.get(key, {})
    if ent.get("done") and not force and time.time() - ent.get("ts", 0) < RECON_TTL:
        ent["state"] = "cached"
        return ent
    if RECON_PROVIDER == "none":
        return {"state": "done", "scan": "disabled", "status": "DISABLED",
                "done": False, "ts": time.time(), "count": 0, "results": []}
    if RECON_PROVIDER == "webhook":
        return _recon_webhook(key, ip, force)
    try:
        scans = spider("/scanlist", timeout=15) or []
    except Exception as e:
        return {"state": "error", "error": "spiderfoot unreachable at " + SPIDER +
                " (" + type(e).__name__ + "): start it with "
                "docker compose --profile recon up -d --build"}
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


def classify_accept(user, ip, failed_ips, mine):
    """Decide if an Accepted login is suspicious. Suspicious accepts are NEVER
    masked — a brute-forcer that guesses correctly must stay fully visible.

    Rules:
    - fail-then-accept: this IP already appears in failed/probe stats -> suspicious.
    - unknown-ip: TRUSTED_IPS is configured and ip not in it (and not self) -> suspicious.
    - unknown-user: TRUSTED_USERS is configured and user not in it -> suspicious.
    Without TRUSTED_* configured, only fail-then-accept flags (zero-config safe).
    Attacker IPs are always shown fully — no PII masking there.
    """
    reasons = []
    if ip in failed_ips:
        reasons.append("fail-then-accept")
    if TRUSTED_IPS and ip not in TRUSTED_IPS and ip not in mine:
        reasons.append("unknown-ip")
    if TRUSTED_USERS and user not in TRUSTED_USERS:
        reasons.append("unknown-user")
    suspicious = bool(reasons)
    return suspicious, "+".join(reasons), (not suspicious)


def summary(host=None):
    lines = read_lines(host or "all")
    now = datetime.now()
    mine = own_ips()
    skipped_self = 0
    skipped_white = 0
    pair_counts, per_ip, hours, ok_hours = Counter(), Counter(), defaultdict(int), defaultdict(int)
    logins = []
    for ln in lines:
        m = FAIL_RE.search(ln) or INVALID_RE.search(ln)
        if m:
            if m.group(2) in mine:
                skipped_self += 1
                continue
            if m.group(2) in WHITELIST_IPS:
                skipped_white += 1
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
            if m.group(1) in WHITELIST_IPS:
                skipped_white += 1
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
    # Second pass: flag suspicious accepts now that failed-IP set is complete.
    # Accepted usernames stay masked in every mode. Only suspicious accepts
    # show full user plus IP (compromise must stay visible).
    failed_ips = set(per_ip.keys())
    enriched = []
    for e in logins:
        suspicious, reason, trusted = classify_accept(e["user"], e["ip"], failed_ips, mine)
        user_out = e["user"] if suspicious else mask_user(e["user"])
        enriched.append({"user": user_out, "user_display": user_out,
                         "ip": e["ip"], "ts": e["ts"],
                         "suspicious": suspicious, "trusted": trusted,
                         "reason": reason})
    logins = enriched
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
    strict = (PRIVACY_MODE == "strict")
    self_ips_out = [mask_ip(ip) for ip in sorted(mine)] if strict else sorted(mine)
    return {"total": sum(per_ip.values()), "ips": len(per_ip), "top": top,
            "timeline": tl, "logins": logins[-60:],
            "suspicious_count": sum(1 for e in logins if e.get("suspicious")),
            "privacy_mode": PRIVACY_MODE,
            "trusted_configured": bool(TRUSTED_IPS or TRUSTED_USERS),
            "excluded_self": skipped_self, "excluded_whitelisted": skipped_white,
            "self_ips": self_ips_out,
            "geo_cached": sum(1 for k in _cache if k.startswith("geo:")),
            "now": _epoch_ms(now), "host": host or "all",
            "hosts": list_hosts()}


_abusers_cache = {"ts": 0.0, "host": None, "entries": []}
_abusers_hits = {}


def _abusers_limited(client):
    now = time.time()
    arr = [t for t in _abusers_hits.get(client, []) if now - t < 60]
    arr.append(now)
    _abusers_hits[client] = arr[-(ABUSERS_RPM + 20):]
    return len(arr) > ABUSERS_RPM


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _abusers_page():
    """Public leaderboard HTML. Attacker rows only — same safe fields."""
    try:
        entries = abusers(None)[:100]
    except Exception:
        entries = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    rows = []
    for i, e in enumerate(entries, 1):
        loc = ", ".join(x for x in (e.get("city"), e.get("country")) if x) or e.get("cc", "")
        users = ", ".join("%s (%d)" % (x["user"], x["hits"]) for x in e["users"][:4])
        tip = html.escape("; ".join(e.get("reasons", [])), quote=True)
        rows.append(
            "<tr><td>%d</td><td class=mono>%s</td><td>%d</td>"
            "<td><span class='band %s' title='%s'>%d %s</span></td>"
            "<td>%s</td><td class=mono>%s</td></tr>" % (
                i, html.escape(e["ip"]), e["hits"], e["band"], tip,
                e["risk"], e["band"], html.escape(loc), html.escape(users)))
    body = "".join(rows) or "<tr><td colspan=6>No listed attackers right now.</td></tr>"
    return ("""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'>
<title>SSH Sentinel — public abusers</title>
<style>body{background:#0a0f1c;color:#dbe4f3;font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px;max-width:1000px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#8b98ad;margin-bottom:16px}
table{width:100%%;border-collapse:collapse;font-size:13px}
td,th{border-bottom:1px solid #1e2a3f;padding:7px 10px;text-align:left}
th{color:#8b98ad;font-size:12px}.mono{font-family:ui-monospace,monospace}
.band{border-radius:20px;padding:1px 10px;font-size:12px}
.low{background:#3fb95022;color:#7ee787}.medium{background:#d2992222;color:#e8b93e}
.high{background:#f0883e22;color:#f0883e}.critical{background:#f8514922;color:#ff9d97}
a{color:#58a6ff}.note{color:#8b98ad;font-size:12px;margin-top:14px}</style>
</head><body>
<h1>🛡️ SSH Sentinel — public abusers</h1>
<div class=sub>%d repeat attackers · updated %s · JSON: <a href="/api/abusers">/api/abusers</a></div>
<table><tr><th>#</th><th>IP</th><th>Hits</th><th>Risk</th><th>Origin</th><th>Users tried</th></tr>%s</table>
<p class=note>Repeat SSH attackers only (5+ fails, scored, no successful logins,
never whitelisted or private IPs). Is your IP here by mistake? Ask the server
admin to add it to WHITELIST_IPS.</p>
</body></html>""" % (len(entries), now, body))


def abusers(host=None):
    """Public-safe attacker feed: repeat offenders only.

    Lists an IP only when it has ABUSERS_MIN_HITS fails, a risk score at
    or above ABUSERS_MIN_SCORE, no successful login, and no whitelist
    entry — so a forgetful owner is never published. Each entry carries
    its risk score, band, and reasons. Cached ABUSERS_TTL seconds.

    NEVER exposes accepted logins, hostnames, internal/self IPs, or raw
    log lines.
    """
    host = host or "all"
    now_t = time.time()
    if (_abusers_cache["host"] == host and _abusers_cache["entries"]
            and now_t - _abusers_cache["ts"] < ABUSERS_TTL):
        return _abusers_cache["entries"]
    lines = read_lines(host)
    now = datetime.now()
    mine = own_ips()
    per_ip = Counter()
    users = defaultdict(Counter)
    accepted = set()
    first = {}
    last = {}
    for ln in lines:
        am = ACCEPT_RE.search(ln)
        if am:
            accepted.add(am.group(2))
            continue
        grp = None
        m = FAIL_RE.search(ln) or INVALID_RE.search(ln)
        if m:
            grp = (m.group(1), m.group(2))
        else:
            m2 = CLOSED_RE.search(ln) or DISC_RE.search(ln)
            if m2 and is_public_ip(m2.group(1)):
                grp = ("?", m2.group(1))
        if not grp:
            continue
        u, ip = grp
        if ip in mine or ip in WHITELIST_IPS or not is_public_ip(ip):
            continue
        per_ip[ip] += 1
        users[ip][u] += 1
        ts = parse_ts(ln, now)
        if ts:
            e = _epoch_ms(ts)
            if ip not in first or e < first[ip]:
                first[ip] = e
            if ip not in last or e > last[ip]:
                last[ip] = e
    cands = [(ip, hits) for ip, hits in per_ip.most_common(200)
             if hits >= ABUSERS_MIN_HITS]
    geo_lookup([ip for ip, _ in cands])
    # External abuse intel only for IPs that pass the local bar (saves quota).
    ext = {}
    if ABUSEIPDB_KEY:
        for ip, _ in cands[:50]:
            ext[ip] = abuse_score(ip)
    entries = []
    for ip, hits in per_ip.most_common(500):
        if hits < ABUSERS_MIN_HITS:
            continue
        g = _cache.get("geo:" + ip, {})
        top_users = users[ip].most_common(5)
        score, band, reasons = risk_of(hits, len(users[ip]), last.get(ip),
                                       ip in accepted, ext.get(ip, 0))
        if score < ABUSERS_MIN_SCORE or ip in accepted:
            continue
        entries.append({
            "ip": ip, "hits": hits,
            "first": first.get(ip), "last": last.get(ip),
            "users": [{"user": u, "hits": c} for u, c in top_users],
            "attempted_users": [u for u, _ in top_users],
            "cc": g.get("cc", ""), "country": g.get("country", ""),
            "city": g.get("city", ""), "org": g.get("org", "") or g.get("isp", ""),
            "asn": g.get("as", ""), "lat": g.get("lat"), "lon": g.get("lon"),
            "flag": flag(g.get("cc", "")),
            "risk": score, "band": band, "reasons": reasons})
    entries.sort(key=lambda e: (-e["risk"], -e["hits"]))
    _abusers_cache.update({"ts": now_t, "host": host, "entries": entries})
    return entries


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




class H(BaseHTTPRequestHandler):
    server_version = "sshlog/4.0"

    MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript",
            ".css": "text/css", ".json": "application/json",
            ".svg": "image/svg+xml", ".png": "image/png",
            ".ico": "image/x-icon", ".woff2": "font/woff2",
            ".woff": "font/woff", ".map": "application/json"}

    @staticmethod
    def serve_dist(path):
        """Serve React build from dist/; None if missing (caller sends 404)."""
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

    def _send(self, body, ctype="text/html; charset=utf-8", code=200, headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        items = headers.items() if isinstance(headers, dict) else (headers or [])
        for k, v in items:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _basic_user(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return ""
        try:
            creds = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace")
        except (ValueError, binascii.Error):
            return ""
        user, _, pw = creds.partition(":")
        if not user or not pw:
            return ""
        expect_user = _effective_local_user()
        if user != expect_user:
            return ""
        return user if _verify_local_password(pw) else ""

    def _forward_user(self):
        for h in FWD_USER_HEADERS:
            v = (self.headers.get(h, "") or "").strip()
            if v:
                return v
        return ""

    def _gate(self):
        """UI/API gate. Returns (user, None) or (None, (code, msg))."""
        if AUTH_MODE == "none":
            return None, None
        if AUTH_MODE == "oidc":
            u = _oidc_session_user(self.headers.get("Cookie", ""))
            if u:
                return u, None
            if self.path.split("?")[0].startswith("/api/"):
                return None, (401, "oidc login required")
            return None, (302, "/oidc/login")
        if AUTH_MODE == "forward":
            if not _via_trusted_proxy(self.client_address[0]):
                return None, (401, "untrusted proxy: SSO identity only accepted "
                                   "from AUTH_TRUSTED_PROXIES")
            u = self._forward_user()
            if not u:
                return None, (401, "missing SSO identity header: ForwardAuth "
                                   "(Authentik/Authelia) or Cloudflare Access must "
                                   "pass an authenticated user")
            if AUTH_ALLOWED_USERS and u not in AUTH_ALLOWED_USERS \
                    and u.split("@")[0] not in AUTH_ALLOWED_USERS:
                return None, (403, "user not allowed")
            return u, None
        u = self._basic_user()
        if not u:
            if not _local_configured():
                return None, (401, "setup needed: open Admin setup with the one-time "
                                   "token from DATA_DIR/setup.token or ADMIN_SETUP_TOKEN, "
                                   "POST /api/admin/setup — or set AUTH_USER + "
                                   "AUTH_PASS_HASH (`server.py genhash`)")
            return None, (401, "login required")
        return u, None

    def _client_ip(self):
        fwd = (self.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()
        return fwd or self.client_address[0]

    def _deny(self, gate):
        code, msg = gate
        if code == 302:
            return self._send("<a href='%s'>sign in</a>" % msg, "text/html",
                              302, {"Location": msg})
        body = json.dumps({"error": msg, "mode": AUTH_MODE})
        if AUTH_MODE == "local" and code == 401:
            return self._send(body, "application/json", 401,
                              {"WWW-Authenticate": 'Basic realm="ssh-sentinel"'})
        return self._send(body, "application/json", code)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/healthz":
            return self._send(b"ok", "text/plain")
        if u.path == "/api/health":
            try:
                return self._send(json.dumps(health()), "application/json")
            except Exception as e:
                return self._send(json.dumps({"status": "error",
                                               "error": type(e).__name__}),
                                   "application/json", 500)
        if u.path in ("/oidc/login", "/oidc/callback", "/oidc/logout"):
            return self._oidc_route(u, q)
        if u.path == "/api/auth":
            user, _ = self._gate() if AUTH_MODE != "none" else (None, None)
            if AUTH_MODE != "none" and user is None:
                # Report mode without leaking identity; UI uses this for the lock badge.
                return self._send(json.dumps(auth_status()), "application/json")
            return self._send(json.dumps(auth_status(user)), "application/json")
        if u.path == "/api/admin/status":
            return self._send(json.dumps(admin_status()), "application/json")
        if u.path == "/api/version":
            # Open build info: version, commit, changelog. No secrets.
            try:
                return self._send(json.dumps(version_info()), "application/json")
            except Exception as e:
                return self._send(json.dumps({"error": type(e).__name__}),
                                   "application/json", 500)
        if u.path == "/api/self":
            # "Is my IP flagged?" — open to all, reveals only the caller's
            # own address and its list status. Powers the UI self-check.
            me = self._client_ip()
            mine = ipaddress.ip_address(me) if _is_ip(me) else None
            try:
                entries = abusers(None)
            except Exception:
                entries = []
            hit = next((e for e in entries if e["ip"] == me), None)
            if mine is not None and not mine.is_global:
                msg = "your address is not a public IP — nothing to check"
            elif me in WHITELIST_IPS:
                msg = "your IP is whitelisted by the admin — you are clear"
            elif hit:
                msg = ("your IP %s has %d failed attempts (risk %d/%s). "
                       "If this is you, ask the admin to whitelist you "
                       "via WHITELIST_IPS." % (me, hit["hits"], hit["risk"], hit["band"]))
            else:
                msg = "your IP is not on the attacker list — you are clear"
            return self._send(json.dumps({
                "ip": me, "whitelisted": me in WHITELIST_IPS,
                "listed": hit is not None,
                "hits": hit["hits"] if hit else 0,
                "risk": hit["risk"] if hit else 0,
                "band": hit["band"] if hit else "clear",
                "first": hit["first"] if hit else None,
                "last": hit["last"] if hit else None,
                "message": msg}), "application/json")
        if u.path == "/abusers":
            if not ABUSERS_PUBLIC:
                return self._send(json.dumps({"error": "public list is off "
                                                       "(ABUSERS_PUBLIC=1 enables it)"}),
                                  "application/json", 404)
            return self._send(_abusers_page(), "text/html; charset=utf-8")
        if u.path == "/api/abusers":
            # Safe fields only, but behind the UI gate unless the owner
            # opens it explicitly with ABUSERS_PUBLIC=1.
            if not ABUSERS_PUBLIC:
                user, gate = self._gate()
                if gate is not None:
                    return self._deny(gate)
            client = self._client_ip()
            if _abusers_limited(client):
                return self._send(json.dumps({"error": "rate limited"}),
                                    "application/json", 429, {"Retry-After": "60"})
            try:
                page = max(1, min(1000, int(q.get("page", ["1"])[0])))
            except ValueError:
                page = 1
            try:
                per = max(1, min(200, int(q.get("per_page", [q.get("per", ["50"])[0]])[0])))
            except ValueError:
                per = 50
            host = (q.get("host", [""])[0] or "")[:64] or None
            try:
                entries = abusers(host)
            except Exception as e:
                return self._send(json.dumps({"error": type(e).__name__}),
                                   "application/json", 500)
            total = len(entries)
            start = (page - 1) * per
            return self._send(json.dumps({
                "abusers": entries[start:start + per],
                "page": page, "per_page": per, "total": total,
                "pages": (total + per - 1) // per if per else 0,
                "host": host or "all", "now": int(time.time() * 1000)}),
                "application/json")
        user, gate = self._gate()
        if gate is not None:
            # Browsers hitting the SPA get the native login prompt in local mode.
            if AUTH_MODE == "local" and gate[0] == 401 and self.path.split("?")[0] not in (
                    "/api/summary", "/api/hosts", "/api/ipinfo", "/api/tail"):
                return self._send("<h1>401 login required</h1>", "text/html", 401,
                                  {"WWW-Authenticate": 'Basic realm="ssh-sentinel"'})
            return self._deny(gate)
        self._auth_user = user
        if u.path == "/api/admin/bans":
            return self._send(json.dumps({"bans": ban_list_active()}), "application/json")
        if u.path == "/api/admin/activity":
            try:
                lim = max(1, min(500, int(q.get("limit", ["200"])[0])))
            except ValueError:
                lim = 200
            return self._send(json.dumps({"activity": activity_list(lim)}),
                              "application/json")
        if u.path == "/api/admin/reports":
            try:
                c = db()
                try:
                    rows = c.execute("SELECT ip, provider, ts, status, detail FROM reports"
                                     " ORDER BY ts DESC LIMIT 200").fetchall()
                finally:
                    c.close()
                reps = [{"ip": ip, "provider": p, "ts": int(t * 1000),
                         "status": s, "detail": d} for ip, p, t, s, d in rows]
            except Exception:
                reps = []
            return self._send(json.dumps({"reports": reps}), "application/json")
        if u.path == "/api/admin/banstate":
            ip = (q.get("ip", [""])[0] or "")[:45]
            return self._send(json.dumps({"ip": ip, "ban": ban_state(ip),
                                          "reports": report_state(ip)}),
                              "application/json")
        if u.path == "/api/banlist":
            lines = [b["ip"] for b in ban_list_active()]
            return self._send("\n".join(lines) + ("\n" if lines else ""),
                              "text/plain")
        if u.path == "/api/summary":
            try:
                host = (q.get("host", [""])[0] or "")[:64] or None
                s = summary(host)
                maybe_alert(s)
                return self._send(json.dumps(s), "application/json")
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
            d["ban"] = ban_state(ip)
            d["reports"] = report_state(ip)
            return self._send(json.dumps(d), "application/json")
        if u.path == "/api/tail":
            filt = (q.get("q", [""])[0] or "")[:64].lower()
            try:
                n = max(10, min(2000, int(q.get("n", ["200"])[0])))
            except ValueError:
                n = 200
            host = (q.get("host", [""])[0] or "")[:64] or None
            lines = read_lines(host)
            # Privacy: drop non-sshd noise (sudo/CRON leak cwd/commands),
            # sanitize the rest. Attacker IPs + Accepted lines stay fully
            # visible — compromise detection must not be masked.
            cleaned = []
            dropped = 0
            for ln in lines:
                if not is_sshd_line(ln):
                    dropped += 1
                    continue
                cleaned.append(sanitize_line(ln))
            out = [ln for ln in cleaned if filt in ln.lower()]
            body = "".join(out[-n:])
            if dropped and not filt:
                body = ("# note: %d non-sshd lines hidden by SHIP_FILTER=sshd-only "
                        "(sudo/CRON noise). Use SHIP_FILTER=full to debug.\n" % dropped) + body
            return self._send(body, "text/plain")
        # React SPA from dist/ (ships in the image; build with npm run build).
        hit = self.serve_dist(u.path)
        if hit is not None:
            body, ctype = hit
            return self._send(body, ctype)
        return self._send("not found (UI dist/ missing — build the frontend)",
                           "text/plain", 404)

    def _oidc_route(self, u, q):
        import secrets as _secrets
        _oidc_prune()
        if AUTH_MODE != "oidc":
            return self._send(json.dumps({"error": "built-in SSO is off "
                                                   "(AUTH_MODE=oidc enables it)"}),
                              "application/json", 404)
        if u.path == "/oidc/logout":
            tok = _cookies(self.headers.get("Cookie", "")).get("ssh_session", "")
            _oidc_sessions.pop(tok, None)
            return self._send("<a href='/'>signed out</a>", "text/html", 302,
                              [("Location", "/"),
                               ("Set-Cookie", _cookie_str("ssh_session", "", clear=True))])
        if u.path == "/oidc/login":
            if not _oidc_configured():
                return self._send(json.dumps({"error": "OIDC not configured: set "
                                                       "OIDC_ISSUER, OIDC_CLIENT_ID, "
                                                       "OIDC_CLIENT_SECRET, OIDC_REDIRECT_URL"}),
                                  "application/json", 500)
            try:
                conf = _oidc_discovery()
            except Exception as e:
                return self._send(json.dumps({"error": "OIDC discovery failed: " +
                                                       type(e).__name__}),
                                  "application/json", 502)
            state = _secrets.token_urlsafe(24)
            nonce = _secrets.token_urlsafe(24)
            _oidc_states[state] = {"nonce": nonce, "ts": time.time()}
            dest = conf["authorization_endpoint"] + "?" + urlencode({
                "client_id": OIDC_CLIENT_ID, "redirect_uri": OIDC_REDIRECT_URL,
                "response_type": "code", "scope": OIDC_SCOPES,
                "state": state, "nonce": nonce})
            return self._send("<a href='%s'>continue to SSO</a>" % dest, "text/html",
                              302, [("Location", dest),
                                    ("Set-Cookie", _cookie_str("oidc_state", state, max_age=600))])
        # /oidc/callback
        state = (q.get("state", [""])[0] or "")
        code = (q.get("code", [""])[0] or "")
        expect = _cookies(self.headers.get("Cookie", "")).get("oidc_state", "")
        saved = _oidc_states.pop(state, None) if state else None
        if not state or not code or not saved or state != expect:
            return self._send(json.dumps({"error": "bad SSO response (state mismatch)"}),
                              "application/json", 401)
        try:
            conf = _oidc_discovery()
            tok = http_form(conf["token_endpoint"], {
                "grant_type": "authorization_code", "code": code,
                "redirect_uri": OIDC_REDIRECT_URL,
                "client_id": OIDC_CLIENT_ID, "client_secret": OIDC_CLIENT_SECRET},
                timeout=20)
        except Exception as e:
            return self._send(json.dumps({"error": "code exchange failed: " + type(e).__name__}),
                              "application/json", 502)
        try:
            claims = _verify_id_token(tok.get("id_token", ""), saved["nonce"])
        except Exception as e:
            return self._send(json.dumps({"error": "login rejected: " + str(e)[:120]}),
                              "application/json", 401)
        user = str(claims.get("email") or claims.get("preferred_username")
                   or claims.get("sub") or "")
        if not user:
            return self._send('{"error":"login rejected: no identity in token"}',
                              "application/json", 401)
        if AUTH_ALLOWED_USERS and user not in AUTH_ALLOWED_USERS \
                and user.split("@")[0] not in AUTH_ALLOWED_USERS:
            return self._send('{"error":"user not allowed"}', "application/json", 403)
        sess = _secrets.token_urlsafe(32)
        _oidc_sessions[sess] = {"user": user, "exp": time.time() + OIDC_SESSION_TTL}
        return self._send("<a href='/'>open dashboard</a>", "text/html", 302,
                          [("Location", "/"),
                           ("Set-Cookie", _cookie_str("ssh_session", sess,
                                                     max_age=OIDC_SESSION_TTL)),
                           ("Set-Cookie", _cookie_str("oidc_state", "", clear=True))])

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0 or length > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, OSError):
            return {}

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/api/admin/setup":
            body = self._read_json()
            if _local_configured():
                return self._send(json.dumps({"error": "setup closed"}),
                                  "application/json", 410)
            tok, _ = _setup_token()
            if not tok or str(body.get("token", "")) != tok:
                return self._send(json.dumps({"error": "bad setup token"}),
                                  "application/json", 403)
            user = str(body.get("user", "")).strip()[:64] or "admin"
            pw = str(body.get("password", ""))
            if len(pw) < 8:
                return self._send(json.dumps({"error": "password too short (min 8)"}),
                                  "application/json", 400)
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                with open(ADMIN_FILE, "w") as f:
                    json.dump({"user": user, "pass_hash": _mint_pass_hash(pw)}, f)
                try:
                    os.chmod(ADMIN_FILE, 0o600)
                except OSError:
                    pass
                try:
                    os.remove(SETUP_TOKEN_FILE)
                except OSError:
                    pass
            except OSError as e:
                return self._send(json.dumps({"error": type(e).__name__}),
                                  "application/json", 500)
            activity_log(user, "setup", "", "initial admin created")
            return self._send(json.dumps({"ok": True, "user": user}), "application/json")
        if u.path == "/api/alerts/test":
            _, gate = self._gate()
            if gate is not None:
                return self._deny(gate)
            if not ALERT_WEBHOOK_URL:
                return self._send(json.dumps({"ok": False,
                                               "error": "ALERT_WEBHOOK_URL is empty"}),
                                   "application/json", 400)
            ok = _alert_send("test.ping", {"msg": "ssh-sentinel test alert"})
            return self._send(json.dumps({"ok": ok}), "application/json")
        if u.path == "/api/recon":
            _, gate = self._gate()
            if gate is not None:
                return self._deny(gate)
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
        actor_user, gate = self._gate()
        if gate is not None:
            return self._deny(gate)
        actor = actor_user or "admin"
        if u.path == "/api/admin/ban":
            body_get = self._read_json()
            v = str(body_get.get("ip", ""))
            if not v and q.get("ip"):
                v = str(q["ip"][0])
            ip = v[:45]
            reason = str(body_get.get("reason", ""))[:200]
            r = ban_add(ip, reason, "manual", actor)
            code = 200 if r.get("ok") else 400
            return self._send(json.dumps(r), "application/json", code)
        if u.path == "/api/admin/unban":
            body_get = self._read_json()
            v = str(body_get.get("ip", ""))
            if not v and q.get("ip"):
                v = str(q["ip"][0])
            ip = v[:45]
            r = ban_remove(ip, actor)
            code = 200 if r.get("ok") else 400
            return self._send(json.dumps(r), "application/json", code)
        if u.path == "/api/admin/password":
            body = self._read_json()
            if AUTH_MODE != "local":
                return self._send(json.dumps({"error": "password change is local mode only"}),
                                  "application/json", 400)
            old = str(body.get("old", ""))
            new = str(body.get("new", ""))
            if not _verify_local_password(old):
                return self._send(json.dumps({"error": "old password wrong"}),
                                  "application/json", 403)
            if len(new) < 8:
                return self._send(json.dumps({"error": "password too short (min 8)"}),
                                  "application/json", 400)
            if AUTH_PASS_HASH or _AUTH_PASSWORD:
                return self._send(json.dumps({"error": "env credential in use: set AUTH_PASS_HASH instead"}),
                                  "application/json", 409)
            try:
                f = _read_admin_file()
                user = f.get("user", "") or _effective_local_user()
                with open(ADMIN_FILE, "w") as fh:
                    json.dump({"user": user, "pass_hash": _mint_pass_hash(new)}, fh)
                try:
                    os.chmod(ADMIN_FILE, 0o600)
                except OSError:
                    pass
            except OSError as e:
                return self._send(json.dumps({"error": type(e).__name__}),
                                  "application/json", 500)
            activity_log(actor, "password", "", "admin password changed")
            return self._send(json.dumps({"ok": True}), "application/json")
        if u.path == "/api/admin/report":
            body_get = self._read_json()
            v = str(body_get.get("ip", ""))
            if not v and q.get("ip"):
                v = str(q["ip"][0])
            ip = v[:45]
            try:
                hits = int(body_get.get("hits", REPORT_MIN_HITS) or REPORT_MIN_HITS)
            except (ValueError, TypeError):
                hits = REPORT_MIN_HITS
            try:
                risk = int(body_get.get("risk", REPORT_MIN_RISK) or REPORT_MIN_RISK)
            except (ValueError, TypeError):
                risk = REPORT_MIN_RISK
            band = str(body_get.get("band", "high"))[:20]
            r = report_ip(ip, hits, risk, band, actor)
            code = 200 if r.get("ok") else 400
            return self._send(json.dumps(r), "application/json", code)
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

    if len(_sys.argv) >= 2 and _sys.argv[1] == "genhash":
        # Mint AUTH_PASS_HASH for local login: `server.py genhash`
        # (prompts securely) or `server.py genhash <password>` (warns: shell history).
        import getpass as _gp
        import secrets as _sec
        if len(_sys.argv) >= 3:
            print("warning: password on the command line lands in shell history; "
                  "prefer bare `server.py genhash` for the hidden prompt.")
            pw = _sys.argv[2]
        else:
            pw = _gp.getpass("new UI password: ")
            if pw != _gp.getpass("repeat UI password: "):
                print("mismatch; aborting.")
                _sys.exit(1)
        if not pw:
            print("empty password; aborting.")
            _sys.exit(1)
        salt = _sec.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200000)
        print("AUTH_PASS_HASH=pbkdf2-sha256$200000$%s$%s"
              % (salt.hex(), dk.hex()))
        print("(set AUTH_USER=%s + this hash; never commit either)" % AUTH_USER)
        _sys.exit(0)

    if len(_sys.argv) >= 2 and _sys.argv[1] == "scrub":
        # Rewrite stored agent logs through the sshd-only allowlist +
        # sanitize. Use after enabling privacy to purge old sudo/CRON lines:
        #   docker exec ssh-sentinel python3 /srv/server.py scrub
        total_kept, total_dropped = 0, 0
        if os.path.isdir(HOSTS_DIR):
            for fn in sorted(os.listdir(HOSTS_DIR)):
                if not fn.endswith(".jsonl"):
                    continue
                p = os.path.join(HOSTS_DIR, fn)
                try:
                    with open(p, errors="replace") as f:
                        src = f.readlines()
                except OSError as e:
                    print("skip %s: %s" % (fn, e))
                    continue
                kept = [sanitize_line(ln) for ln in src if is_sshd_line(ln)]
                dropped = len(src) - len(kept)
                try:
                    with open(p, "w") as f:
                        f.writelines(kept[-MAX_LINES_PER_HOST:])
                    os.chmod(p, 0o600)
                    with open(p + ".meta", "w") as f:
                        json.dump({"host": fn[:-6], "last_seen": time.time(),
                                   "lines": len(kept[-MAX_LINES_PER_HOST:])}, f)
                except OSError as e:
                    print("write %s failed: %s" % (fn, e))
                    continue
                total_kept += len(kept)
                total_dropped += dropped
                print("%s: kept %d, dropped %d" % (fn, len(kept), dropped))
        print("done: kept %d, dropped %d (mode=%s filter=%s)" % (
            total_kept, total_dropped, PRIVACY_MODE, SHIP_FILTER))
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
    try:
        db_init()
    except Exception as e:
        print("db: init failed (%s)" % type(e).__name__, flush=True)
    if AUTH_MODE == "local" and not _local_configured():
        tok = _ensure_setup_token()
        print("auth: MODE=local setup needed — open Admin setup with one-time token", flush=True)
        print("auth: token source=%s (file %s or ADMIN_SETUP_TOKEN)" % (
            "env" if os.environ.get("ADMIN_SETUP_TOKEN", "").strip() else "file",
            SETUP_TOKEN_FILE), flush=True)
        if not tok:
            print("auth: setup token missing — set ADMIN_SETUP_TOKEN", flush=True)
    threading.Thread(target=_ops_loop, daemon=True).start()
    print("ops: bans auto=%s threshold=%d/%ds jail=%s reports=%s provider=%s" % (
        BAN_AUTO, BAN_THRESHOLD, BAN_WINDOW, BAN_JAIL,
        REPORT_ENABLED, REPORT_PROVIDER), flush=True)
    if AUTH_MODE == "none":
        print("auth: MODE=none (open) — keep 8079 on tailnet/localhost or behind SSO; "
              "set AUTH_MODE=local|forward for login", flush=True)
    elif AUTH_MODE == "forward":
        print("auth: MODE=forward (ForwardAuth/OIDC via %s%s, proxies=%d nets)" % (
            ",".join(FWD_USER_HEADERS[:2]),
            " allowlist=%d" % len(AUTH_ALLOWED_USERS) if AUTH_ALLOWED_USERS else "",
            len(_TRUSTED_PROXY_NETS)), flush=True)
    elif AUTH_MODE == "oidc":
        print("auth: MODE=oidc issuer=%s creds=%s" % (
            OIDC_ISSUER or "MISSING",
            "configured" if _oidc_configured() else "MISSING (login disabled)"),
            flush=True)
    else:
        print("auth: MODE=local user=%s creds=%s" % (
            _effective_local_user(),
            "configured" if _local_configured() else "MISSING (deny-all)"),
            flush=True)
    httpd = ThreadingHTTPServer(("0.0.0.0", 8079), H)
    if TLS_CERT and TLS_KEY:
        import ssl as _ssl
        _ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        _ctx.minimum_version = _ssl.TLSVersion.TLSv1_3
        _ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        httpd.socket = _ctx.wrap_socket(httpd.socket, server_side=True)
        print("tls: 1.3-only on :8079 (cert %s)" % TLS_CERT, flush=True)
    httpd.serve_forever()
