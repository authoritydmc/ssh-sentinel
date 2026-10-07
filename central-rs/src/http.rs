//! HTTP server and routing. Mirrors backend/server.py paths and payloads.

use crate::auth;
use crate::config::{Cfg, Eff};
use crate::db::Db;
use crate::stats;
use std::collections::HashMap;
use std::sync::Mutex;
use tiny_http::{Header, Server};

pub struct State {
    pub cfg: Cfg,
    pub db: Db,
    pub start_ms: i64,
    pub abusers_hits: Mutex<HashMap<String, Vec<i64>>>,
}

pub struct Req {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub remote: String,
}

pub struct Resp {
    pub status: u16,
    pub ctype: String,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl Resp {
    fn json(status: u16, v: &serde_json::Value) -> Resp {
        Resp { status, ctype: "application/json".to_string(), body: v.to_string().into_bytes(), headers: vec![] }
    }
    fn text(status: u16, ctype: &str, body: Vec<u8>) -> Resp {
        Resp { status, ctype: ctype.to_string(), body, headers: vec![] }
    }
}

fn pct_decode(s: &str) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                out.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(' ');
        } else {
            out.push(b[i] as char);
        }
        i += 1;
    }
    out
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for part in q.split('&') {
        if part.is_empty() {
            continue;
        }
        match part.split_once('=') {
            Some((k, v)) => {
                m.insert(pct_decode(k), pct_decode(v));
            }
            None => {
                m.insert(pct_decode(part), String::new());
            }
        }
    }
    m
}

fn read_json(body: &[u8]) -> serde_json::Value {
    if body.is_empty() || body.len() > 65536 {
        return serde_json::Value::Object(Default::default());
    }
    serde_json::from_slice(body).unwrap_or(serde_json::Value::Object(Default::default()))
}

// --- open helpers ---

fn exe_dir() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|x| x.to_string_lossy().to_string()))
        .unwrap_or_else(|| ".".to_string())
}

fn version_info() -> serde_json::Value {
    let mut log = String::new();
    for base in [exe_dir(), ".".to_string()] {
        let p = format!("{}/CHANGELOG.md", base.trim_end_matches('/'));
        if let Ok(t) = std::fs::read_to_string(p) {
            log = t.chars().take(20480).collect();
            break;
        }
    }
    serde_json::json!({
        "version": app_version_g(),
        "commit": crate::util::env("GIT_COMMIT", "").chars().take(12).collect::<String>(),
        "changelog": log,
    })
}

fn app_version_g() -> String {
    // version without cfg (exe-relative files only)
    let v = crate::util::env("APP_VERSION", "").trim().to_string();
    if !v.is_empty() && v != "dev" {
        return v;
    }
    for base in [exe_dir(), ".".to_string()] {
        let p = format!("{}/VERSION", base.trim_end_matches('/'));
        if let Ok(t) = std::fs::read_to_string(p) {
            let t = t.trim().to_string();
            if !t.is_empty() {
                return t;
            }
        }
    }
    if v.is_empty() { "dev".to_string() } else { v }
}

fn auth_status(cfg: &Cfg, eff: &Eff, db: &Db, user: Option<&str>) -> serde_json::Value {
    let login = match cfg.auth_mode.as_str() {
        "none" => "none",
        "forward" => "forward",
        "oidc" => "oidc",
        _ => "basic",
    };
    let safe = matches!(cfg.auth_mode.as_str(), "local" | "forward" | "oidc");
    serde_json::json!({
        "mode": cfg.auth_mode, "login": login,
        "user": user,
        "safe": safe,
        "version": app_version_g(),
        "abusers_public": eff.abusers_public(),
        "setup_needed": cfg.auth_mode == "local" && {
            let f = db.read_admin();
            let file_ok = f.get("user").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                && f.get("pass_hash").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
            cfg.auth_pass_hash.is_empty() && cfg.auth_password.is_empty() && !file_ok
        },
    })
}

fn health(state: &State) -> serde_json::Value {
    let (log_ok, log_size) = match std::fs::metadata(&state.cfg.log) {
        Ok(m) => (true, m.len() as i64),
        Err(_) => (false, 0),
    };
    let hosts = stats::list_hosts(&stats_ctx(state));
    let online = hosts.iter().filter(|h| h.get("online").and_then(|x| x.as_bool()).unwrap_or(false)).count();
    let data_ok = std::fs::create_dir_all(&state.cfg.data_dir).is_ok();
    serde_json::json!({
        "status": "ok", "uptime_s": (crate::clock_ms() - state.start_ms) / 1000,
        "version": app_version_g(), "mode": state.cfg.auth_mode,
        "time": crate::clock_ms(), "hosts": hosts.len(), "hosts_online": online,
        "geo_cached": crate::geo::geo_cached_count(),
        "log_ok": log_ok, "log_bytes": log_size, "data_ok": data_ok,
    })
}

pub fn stats_ctx(state: &State) -> stats::Ctx<'_> {
    stats::Ctx { cfg: &state.cfg, db: &state.db, eff: Eff { db: &state.db } }
}

fn admin_status(state: &State) -> serde_json::Value {
    let eff = Eff { db: &state.db };
    let (tok, _) = auth::setup_token(&state.db);
    let f = state.db.read_admin();
    let file_ok = f.get("user").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
        && f.get("pass_hash").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
    let setup_needed = state.cfg.auth_pass_hash.is_empty()
        && state.cfg.auth_password.is_empty()
        && !file_ok;
    let mut locked = serde_json::Map::new();
    let mut sources = serde_json::Map::new();
    for (key, env_name) in [
        ("ban_enabled", "BAN_ENABLED"), ("ban_jail", "BAN_JAIL"), ("ban_time", "BAN_TIME"),
        ("ban_auto", "BAN_AUTO"), ("ban_threshold", "BAN_THRESHOLD"), ("ban_window", "BAN_WINDOW"),
        ("ban_auto_time", "BAN_AUTO_TIME"), ("report_enabled", "REPORT_ENABLED"),
        ("report_provider", "REPORT_PROVIDER"), ("report_throttle_days", "REPORT_THROTTLE_DAYS"),
        ("report_min_risk", "REPORT_MIN_RISK"), ("report_min_hits", "REPORT_MIN_HITS"),
        ("whitelist_ips", "WHITELIST_IPS"), ("trusted_ips", "TRUSTED_IPS"),
        ("trusted_users", "TRUSTED_USERS"), ("self_public_ips", "SELF_PUBLIC_IPS"),
        ("abusers_min_hits", "ABUSERS_MIN_HITS"), ("abusers_min_score", "ABUSERS_MIN_SCORE"),
        ("abusers_public", "ABUSERS_PUBLIC"),
    ] {
        locked.insert(key.to_string(), serde_json::Value::Bool(eff.locked(env_name)));
        sources.insert(key.to_string(), serde_json::Value::String(eff.source(env_name, key).to_string()));
    }
    serde_json::json!({
        "setup_needed": setup_needed,
        "setup_token_configured": !tok.is_empty(),
        "ban_enabled": eff.ban_enabled(), "ban_auto": eff.ban_auto(),
        "ban_jail": eff.ban_jail(), "ban_threshold": eff.ban_threshold(),
        "ban_window": eff.ban_window(), "ban_time": eff.ban_time(),
        "ban_auto_time": eff.ban_auto_time(),
        "report_enabled": eff.report_enabled(), "report_provider": eff.report_provider(),
        "report_throttle_days": eff.report_throttle(),
        "report_min_risk": eff.report_min_risk(), "report_min_hits": eff.report_min_hits(),
        "whitelist_ips": eff_str_csv(&eff, "WHITELIST_IPS", "whitelist_ips"),
        "trusted_ips": eff_str_csv(&eff, "TRUSTED_IPS", "trusted_ips"),
        "trusted_users": eff_str_csv(&eff, "TRUSTED_USERS", "trusted_users"),
        "self_public_ips": eff_str_csv(&eff, "SELF_PUBLIC_IPS", "self_public_ips"),
        "abusers_min_hits": eff.abusers_min_hits(), "abusers_min_score": eff.abusers_min_score(),
        "abusers_public": eff.abusers_public(),
        "enforce_locked": locked, "enforce_sources": sources,
        "alert_configured": !state.cfg.alert_url.is_empty(),
        "alert_on_success": state.cfg.alert_on_success,
        "alert_spike_threshold": state.cfg.alert_spike_n,
        "alert_spike_window_s": state.cfg.alert_spike_window,
        "auth_mode": state.cfg.auth_mode, "version": app_version_g(),
    })
}

fn eff_str_csv(eff: &Eff, env_name: &str, key: &str) -> String {
    let raw = crate::util::env(env_name, "").trim().to_string();
    if !raw.is_empty() {
        return raw;
    }
    // read back through eff helpers by key
    let mut set: Vec<String> = match key {
        "whitelist_ips" => eff.whitelist().into_iter().collect(),
        "trusted_ips" => {
            let mut t = eff.trusted_ips();
            for x in crate::util::csv_set(&crate::util::env("TRUSTED_IPS", "")) {
                t.remove(&x);
            }
            t.into_iter().collect()
        }
        "trusted_users" => {
            let mut t = eff.trusted_users();
            for x in crate::util::csv_set(&crate::util::env("TRUSTED_USERS", "")) {
                t.remove(&x);
            }
            t.into_iter().collect()
        }
        _ => eff.self_extra().into_iter().collect(),
    };
    set.sort();
    set.join(",")
}

fn abusers_limited(state: &State, client: &str) -> bool {
    let now = crate::clock_secs();
    if let Ok(mut m) = state.abusers_hits.lock() {
        let arr = m.entry(client.to_string()).or_default();
        arr.retain(|t| now - t < 60);
        arr.push(now);
        let over = arr.len() > state.cfg.abusers_rpm;
        if arr.len() > state.cfg.abusers_rpm + 20 {
            let skip = arr.len() - (state.cfg.abusers_rpm + 20);
            arr.drain(..skip);
        }
        return over;
    }
    false
}

fn abusers_page(state: &State) -> String {
    let entries = stats::abusers(&stats_ctx(state), None);
    let top: Vec<&serde_json::Value> = entries.iter().take(100).collect();
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    let mut rows = String::new();
    for (i, e) in top.iter().enumerate() {
        let loc = [
            e.get("city").and_then(|x| x.as_str()).unwrap_or(""),
            e.get("country").and_then(|x| x.as_str()).unwrap_or(""),
        ]
        .into_iter()
        .filter(|x| !x.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
        let loc = if loc.is_empty() { e.get("cc").and_then(|x| x.as_str()).unwrap_or("").to_string() } else { loc };
        let users = e.get("users").and_then(|x| x.as_array()).map(|a| {
            a.iter().take(4).map(|u| {
                format!("{} ({})", u.get("user").and_then(|x| x.as_str()).unwrap_or(""), u.get("hits").and_then(|x| x.as_i64()).unwrap_or(0))
            }).collect::<Vec<_>>().join(", ")
        }).unwrap_or_default();
        let reasons = e.get("reasons").and_then(|x| x.as_array()).map(|a| {
            a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; ")
        }).unwrap_or_default();
        let band = e.get("band").and_then(|x| x.as_str()).unwrap_or("");
        rows.push_str(&format!(
            "<tr><td>{}</td><td class=mono>{}</td><td>{}</td><td><span class='band {}' title='{}'>{} {}</span></td><td>{}</td><td class=mono>{}</td></tr>",
            i + 1,
            esc(e.get("ip").and_then(|x| x.as_str()).unwrap_or("")),
            e.get("hits").and_then(|x| x.as_i64()).unwrap_or(0),
            band,
            esc_attr(&reasons),
            e.get("risk").and_then(|x| x.as_i64()).unwrap_or(0),
            band,
            esc(&loc),
            esc(&users)));
    }
    if rows.is_empty() {
        rows = "<tr><td colspan=6>No listed attackers right now.</td></tr>".to_string();
    }
    format!(r#"<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'>
<title>SSH Sentinel — public abusers</title>
<style>body{{background:#0a0f1c;color:#dbe4f3;font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px;max-width:1000px}}
h1{{font-size:20px;margin:0 0 4px}}.sub{{color:#8b98ad;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
td,th{{border-bottom:1px solid #1e2a3f;padding:7px 10px;text-align:left}}
th{{color:#8b98ad;font-size:12px}}.mono{{font-family:ui-monospace,monospace}}
.band{{border-radius:20px;padding:1px 10px;font-size:12px}}
.low{{background:#3fb95022;color:#7ee787}}.medium{{background:#d2992222;color:#e8b93e}}
.high{{background:#f0883e22;color:#f0883e}}.critical{{background:#f8514922;color:#ff9d97}}
a{{color:#58a6ff}}.note{{color:#8b98ad;font-size:12px;margin-top:14px}}</style>
</head><body>
<h1>🛡️ SSH Sentinel — public abusers</h1>
<div class=sub>{} repeat attackers · updated {} · JSON: <a href="/api/abusers">/api/abusers</a></div>
<table><tr><th>#</th><th>IP</th><th>Hits</th><th>Risk</th><th>Origin</th><th>Users tried</th></tr>{}</table>
<p class=note>Repeat SSH attackers only (5+ fails, scored, no successful logins,
never whitelisted or private IPs). Is your IP here by mistake? Ask the server
admin to add it to WHITELIST_IPS.</p>
</body></html>"#, top.len(), now, rows)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
fn esc_attr(s: &str) -> String {
    esc(s).replace('\'', "&#x27;").replace('"', "&quot;")
}

// --- MIME + dist ---

fn mime(ext: &str) -> &str {
    match ext {
        ".html" => "text/html; charset=utf-8",
        ".js" => "text/javascript",
        ".css" => "text/css",
        ".json" => "application/json",
        ".svg" => "image/svg+xml",
        ".png" => "image/png",
        ".ico" => "image/x-icon",
        ".woff2" => "font/woff2",
        ".woff" => "font/woff",
        ".map" => "application/json",
        _ => "application/octet-stream",
    }
}

fn serve_dist(cfg: &Cfg, path: &str) -> Option<(Vec<u8>, String)> {
    let mut p = path;
    if p == "/" || p == "/ssh" || p == "/index.html" {
        p = "/index.html";
    }
    let mut rel = p.trim_start_matches('/').split('?').next().unwrap_or("").to_string();
    if rel == "ssh" || rel.starts_with("ssh/") {
        rel = rel[3..].trim_start_matches('/').to_string();
    }
    if rel.contains("..") || rel.starts_with("api/") {
        return None;
    }
    let dist = if cfg.dist.trim().is_empty() { exe_dir() + "/dist" } else { cfg.dist.clone() };
    let full = format!("{}/{}", dist.trim_end_matches('/'), rel);
    if std::path::Path::new(&full).is_file() {
        if let Ok(body) = std::fs::read(&full) {
            let ext = std::path::Path::new(&full).extension().and_then(|e| e.to_str()).map(|e| format!(".{}", e.to_lowercase())).unwrap_or_default();
            return Some((body, mime(&ext).to_string()));
        }
    }
    let index = format!("{}/index.html", dist.trim_end_matches('/'));
    if let Ok(body) = std::fs::read(&index) {
        return Some((body, "text/html; charset=utf-8".to_string()));
    }
    None
}

// --- main router ---

pub fn handle(state: &State, req: &Req) -> Resp {
    let q = &req.query;
    let qp = |k: &str| q.get(k).map(|s| s.as_str()).unwrap_or("");
    // open: healthz
    if req.method == "GET" && req.path == "/healthz" {
        return Resp::text(200, "text/plain", b"ok".to_vec());
    }
    if req.method == "GET" && req.path == "/api/health" {
        return Resp::json(200, &health(state));
    }
    if req.method == "GET" && (req.path == "/oidc/login" || req.path == "/oidc/callback" || req.path == "/oidc/logout") {
        let cookies = auth::parse_cookies(req.headers.get("cookie").map(|s| s.as_str()).unwrap_or(""));
        let o = auth::oidc_route(&state.cfg, &req.path, q, &cookies);
        let mut r = Resp::text(o.status, &o.ctype, o.body.into_bytes());
        r.headers = o.headers;
        return r;
    }
    if req.method == "GET" && req.path == "/api/auth" {
        if state.cfg.auth_mode == "none" {
            return Resp::json(200, &auth_status(&state.cfg, &Eff { db: &state.db }, &state.db, None));
        }
        let g = gate_of(state, req);
        if let Some(u) = g.user {
            return Resp::json(200, &auth_status(&state.cfg, &Eff { db: &state.db }, &state.db, Some(&u)));
        }
        return Resp::json(200, &auth_status(&state.cfg, &Eff { db: &state.db }, &state.db, None));
    }
    if req.method == "GET" && req.path == "/api/admin/status" {
        return Resp::json(200, &admin_status(state));
    }
    if req.method == "GET" && req.path == "/api/version" {
        return Resp::json(200, &version_info());
    }
    if req.method == "GET" && req.path == "/api/self" {
        return self_check(state, req);
    }
    if req.method == "GET" && req.path == "/abusers" {
        if !(Eff { db: &state.db }).abusers_public() {
            return Resp::json(404, &serde_json::json!({"error": "public list is off (ABUSERS_PUBLIC=1 enables it)"}));
        }
        return Resp::text(200, "text/html; charset=utf-8", abusers_page(state).into_bytes());
    }
    if req.method == "GET" && req.path == "/api/abusers" {
        if !(Eff { db: &state.db }).abusers_public() {
            let g = gate_of(state, req);
            if let Some(d) = g.deny {
                return deny(state, req, d);
            }
        }
        let client = client_ip(req);
        if abusers_limited(state, &client) {
            let mut r = Resp::json(429, &serde_json::json!({"error": "rate limited"}));
            r.headers.push(("Retry-After".to_string(), "60".to_string()));
            return r;
        }
        let page = qp("page").parse::<i64>().map(|v| v.clamp(1, 1000)).unwrap_or(1);
        let per = q.get("per_page").or_else(|| q.get("per")).and_then(|v| v.parse::<i64>().ok()).map(|v| v.clamp(1, 200)).unwrap_or(50);
        let host = {
            let h: String = qp("host").chars().take(64).collect();
            if h.is_empty() { None } else { Some(h) }
        };
        let entries = stats::abusers(&stats_ctx(state), host.as_deref());
        let total = entries.len() as i64;
        let start = ((page - 1) * per) as usize;
        let slice: Vec<serde_json::Value> = entries.into_iter().skip(start).take(per as usize).collect();
        return Resp::json(200, &serde_json::json!({
            "abusers": slice, "page": page, "per_page": per, "total": total,
            "pages": if per > 0 { (total + per - 1) / per } else { 0 },
            "host": host.unwrap_or_else(|| "all".to_string()), "now": crate::clock_ms()}));
    }
    if req.method == "POST" && req.path == "/api/admin/setup" {
        return admin_setup(state, &read_json(&req.body));
    }
    if req.method == "POST" && req.path == "/api/alerts/test" {
        let g = gate_of(state, req);
        if let Some(d) = g.deny {
            return deny(state, req, d);
        }
        if state.cfg.alert_url.is_empty() {
            return Resp::json(400, &serde_json::json!({"ok": false, "error": "ALERT_WEBHOOK_URL is empty"}));
        }
        let ok = stats::alert_send(&stats_ctx(state), "test.ping", &serde_json::json!({"msg": "ssh-sentinel test alert"}));
        return Resp::json(200, &serde_json::json!({"ok": ok}));
    }
    if req.method == "POST" && req.path == "/api/recon" {
        let g = gate_of(state, req);
        if let Some(d) = g.deny {
            return deny(state, req, d);
        }
        let ip: String = qp("ip").chars().take(45).collect();
        if !crate::util::is_public_ip(&ip) {
            return Resp::json(400, &serde_json::json!({"error": "not a public IP"}));
        }
        let force = qp("force") == "1";
        let v = crate::geo::recon_status(&ip, force, &state.cfg.spider, &state.cfg.recon_modules, &state.cfg.recon_provider, &state.cfg.recon_hook, &state.cfg.recon_token);
        return Resp::json(200, &v);
    }
    if req.method == "POST" && req.path == "/api/agent/push" {
        return agent_push(state, req);
    }
    // gated area
    let g = gate_of(state, req);
    if let Some(d) = g.deny.clone() {
        if state.cfg.auth_mode == "local" && d.0 == 401
            && !["/api/summary", "/api/hosts", "/api/ipinfo", "/api/tail"].contains(&req.path.as_str())
        {
            let mut r = Resp::text(401, "text/html", b"<h1>401 login required</h1>".to_vec());
            r.headers.push(("WWW-Authenticate".to_string(), "Basic realm=\"ssh-sentinel\"".to_string()));
            return r;
        }
        return deny(state, req, d);
    }
    let actor = g.user.unwrap_or_else(|| "admin".to_string());
    if req.method == "GET" && req.path == "/api/admin/bans" {
        return Resp::json(200, &serde_json::json!({"bans": stats::ban_list_active(&state.db)}));
    }
    if req.method == "GET" && req.path == "/api/admin/config" {
        return Resp::json(200, &enforce_config(&state.db));
    }
    if req.method == "GET" && req.path == "/api/admin/activity" {
        let lim = qp("limit").parse::<i64>().unwrap_or(200);
        return Resp::json(200, &serde_json::json!({"activity": state.db.activity_list(lim)}));
    }
    if req.method == "GET" && req.path == "/api/admin/reports" {
        return Resp::json(200, &serde_json::json!({"reports": admin_reports(&state.db)}));
    }
    if req.method == "GET" && req.path == "/api/admin/banstate" {
        let ip: String = qp("ip").chars().take(45).collect();
        return Resp::json(200, &serde_json::json!({"ip": ip, "ban": stats::ban_state(&state.db, &ip), "reports": stats::report_state(&state.db, &ip)}));
    }
    if req.method == "GET" && req.path == "/api/banlist" {
        let lines: Vec<String> = stats::ban_list_active(&state.db).into_iter().filter_map(|b| b.get("ip").and_then(|x| x.as_str()).map(|s| s.to_string())).collect();
        let body = if lines.is_empty() { String::new() } else { lines.join("\n") + "\n" };
        return Resp::text(200, "text/plain", body.into_bytes());
    }
    if req.method == "GET" && req.path == "/api/summary" {
        let host = {
            let h: String = qp("host").chars().take(64).collect();
            if h.is_empty() { None } else { Some(h) }
        };
        let ctx = stats_ctx(state);
        let s = stats::summary(&ctx, host.as_deref());
        stats::maybe_alert(&ctx, &s);
        return Resp::json(200, &s);
    }
    if req.method == "GET" && req.path == "/api/hosts" {
        return Resp::json(200, &serde_json::Value::Array(stats::list_hosts(&stats_ctx(state)).into_iter().collect()));
    }
    if req.method == "GET" && req.path == "/api/ipinfo" {
        let ip: String = qp("ip").chars().take(45).collect();
        if ip.is_empty() {
            return Resp::text(400, "application/json", b"{\"error\":\"missing ip\"}".to_vec());
        }
        let host = {
            let h: String = qp("host").chars().take(64).collect();
            if h.is_empty() { None } else { Some(h) }
        };
        let mut d = crate::geo::ip_detail(&ip);
        d["flag"] = serde_json::Value::String(crate::util::flag(d.get("cc").and_then(|x| x.as_str()).unwrap_or("")));
        d["history"] = stats::ip_history(&stats_ctx(state), &ip, host.as_deref());
        d["ban"] = stats::ban_state(&state.db, &ip);
        d["reports"] = serde_json::Value::Array(stats::report_state(&state.db, &ip).into_iter().collect());
        return Resp::json(200, &d);
    }
    if req.method == "GET" && req.path == "/api/tail" {
        return tail(state, req);
    }
    if req.method == "POST" && req.path == "/api/admin/ban" {
        let b = read_json(&req.body);
        let mut v = b.get("ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if v.is_empty() {
            v = qp("ip").to_string();
        }
        let ip: String = v.chars().take(45).collect();
        let reason: String = b.get("reason").and_then(|x| x.as_str()).unwrap_or("").chars().take(200).collect();
        let r = stats::ban_add(&stats_ctx(state), &ip, &reason, "manual", &actor, None);
        let ok = r.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
        return Resp::json(if ok { 200 } else { 400 }, &r);
    }
    if req.method == "POST" && req.path == "/api/admin/unban" {
        let b = read_json(&req.body);
        let mut v = b.get("ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if v.is_empty() {
            v = qp("ip").to_string();
        }
        let ip: String = v.chars().take(45).collect();
        let r = stats::ban_remove(&stats_ctx(state), &ip, &actor);
        let ok = r.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
        return Resp::json(if ok { 200 } else { 400 }, &r);
    }
    if req.method == "POST" && req.path == "/api/admin/password" {
        return admin_password(state, &actor, &read_json(&req.body));
    }
    if req.method == "POST" && req.path == "/api/admin/report" {
        let b = read_json(&req.body);
        let mut v = b.get("ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if v.is_empty() {
            v = qp("ip").to_string();
        }
        let ip: String = v.chars().take(45).collect();
        let eff = Eff { db: &state.db };
        let hits = b.get("hits").and_then(|x| x.as_i64()).unwrap_or_else(|| eff.report_min_hits());
        let risk = b.get("risk").and_then(|x| x.as_i64()).unwrap_or_else(|| eff.report_min_risk());
        let band: String = b.get("band").and_then(|x| x.as_str()).unwrap_or("high").chars().take(20).collect();
        let r = stats::report_ip(&stats_ctx(state), &ip, hits, risk, &band, &actor);
        let ok = r.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
        return Resp::json(if ok { 200 } else { 400 }, &r);
    }
    if req.method == "POST" && req.path == "/api/admin/config" {
        let b = read_json(&req.body);
        let r = update_config(&state.db, &b, &actor);
        return Resp::json(200, &r);
    }
    // React SPA
    if let Some((body, ctype)) = serve_dist(&state.cfg, &req.path) {
        return Resp::text(200, &ctype, body);
    }
    Resp::text(404, "text/plain", b"not found (UI dist/ missing \xe2\x80\x94 build the frontend)".to_vec())
}

fn gate_of(state: &State, req: &Req) -> auth::Gate {
    let cookies = auth::parse_cookies(req.headers.get("cookie").map(|s| s.as_str()).unwrap_or(""));
    auth::gate(&state.cfg, &state.db, &auth::Req {
        path: &req.path,
        headers: &req.headers,
        cookies,
        remote: req.remote.clone(),
    })
}

fn deny(state: &State, _req: &Req, d: (u16, String)) -> Resp {
    if d.0 == 302 {
        let mut r = Resp::text(302, "text/html", format!("<a href='{}'>sign in</a>", d.1).into_bytes());
        r.headers.push(("Location".to_string(), d.1));
        return r;
    }
    let body = serde_json::json!({"error": d.1, "mode": state.cfg.auth_mode}).to_string().into_bytes();
    let mut r = Resp::text(d.0, "application/json", body);
    if state.cfg.auth_mode == "local" && d.0 == 401 {
        r.headers.push(("WWW-Authenticate".to_string(), "Basic realm=\"ssh-sentinel\"".to_string()));
    }
    r
}

fn client_ip(req: &Req) -> String {
    if let Some(fwd) = req.headers.get("x-forwarded-for") {
        let first = fwd.split(',').next().unwrap_or("").trim();
        if !first.is_empty() {
            return first.to_string();
        }
    }
    req.remote.clone()
}

fn self_check(state: &State, req: &Req) -> Resp {
    let me = client_ip(req);
    let mine_global = me.parse::<std::net::IpAddr>().map(|a| {
        // mirrors: not mine.is_global for the message branch
        is_global_ip(a)
    }).unwrap_or(true);
    let entries = stats::abusers(&stats_ctx(state), None);
    let hit = entries.iter().find(|e| e.get("ip").and_then(|x| x.as_str()) == Some(me.as_str()));
    let eff = Eff { db: &state.db };
    let white = eff.whitelist();
    let (msg, listed) = if !mine_global {
        ("your address is not a public IP — nothing to check".to_string(), false)
    } else if white.contains(&me) {
        ("your IP is whitelisted by the admin — you are clear".to_string(), false)
    } else if let Some(h) = hit {
        (format!("your IP {} has {} failed attempts (risk {}/{}). If this is you, ask the admin to whitelist you via WHITELIST_IPS.",
            me,
            h.get("hits").and_then(|x| x.as_i64()).unwrap_or(0),
            h.get("risk").and_then(|x| x.as_i64()).unwrap_or(0),
            h.get("band").and_then(|x| x.as_str()).unwrap_or("")),
            true)
    } else {
        ("your IP is not on the attacker list — you are clear".to_string(), false)
    };
    Resp::json(200, &serde_json::json!({
        "ip": me, "whitelisted": white.contains(&me), "listed": listed,
        "hits": hit.and_then(|h| h.get("hits").and_then(|x| x.as_i64())).unwrap_or(0),
        "risk": hit.and_then(|h| h.get("risk").and_then(|x| x.as_i64())).unwrap_or(0),
        "band": hit.and_then(|h| h.get("band").and_then(|x| x.as_str())).unwrap_or("clear"),
        "first": hit.and_then(|h| h.get("first").cloned()).unwrap_or(serde_json::Value::Null),
        "last": hit.and_then(|h| h.get("last").cloned()).unwrap_or(serde_json::Value::Null),
        "message": msg}))
}

fn is_global_ip(a: std::net::IpAddr) -> bool {
    // Mirrors Python "not mine.is_global": only loopback/link-local/reserved
    // count as non-global here (ipaddress is_global is False for private too,
    // but the Python message branch checks is_global which is False for
    // private addresses as well). Use util public-plus-private notion:
    // non-global = loopback, link-local, unspecified, multicast, reserved.
    match a {
        std::net::IpAddr::V4(v) => {
            let o = v.octets();
            if v.is_loopback() || v.is_multicast() || v.is_unspecified() {
                return false;
            }
            if o[0] == 0 || o[0] >= 240 {
                return false;
            }
            if o[0] == 169 && o[1] == 254 {
                return false;
            }
            true
        }
        std::net::IpAddr::V6(v) => {
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast())
        }
    }
}

fn tail(state: &State, req: &Req) -> Resp {
    let q = &req.query;
    let filt: String = q.get("q").map(|s| s.chars().take(64).collect::<String>().to_lowercase()).unwrap_or_default();
    let n = q.get("n").and_then(|v| v.parse::<usize>().ok()).map(|v| v.clamp(10, 2000)).unwrap_or(200);
    let host = {
        let h: String = q.get("host").map(|s| s.chars().take(64).collect()).unwrap_or_default();
        if h.is_empty() { None } else { Some(h) }
    };
    let lines = crate::logparse::read_lines(&state.cfg, host.as_deref());
    let mut cleaned = vec![];
    let mut dropped = 0i64;
    for ln in &lines {
        let s = ln.trim_end_matches('\n');
        if !crate::logparse::is_sshd_line(s, state.cfg.privacy_off, state.cfg.ship_full) {
            dropped += 1;
            continue;
        }
        cleaned.push(crate::logparse::sanitize(s, state.cfg.privacy_off));
    }
    let out: Vec<&str> = cleaned.iter().filter(|ln| ln.to_lowercase().contains(&filt)).map(|s| s.as_str()).collect();
    let total = out.len();
    let start = total.saturating_sub(n);
    let mut body = out[start..].join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    if dropped > 0 && filt.is_empty() {
        body = format!("# note: {} non-sshd lines hidden by SHIP_FILTER=sshd-only (sudo/CRON noise). Use SHIP_FILTER=full to debug.\n{}", dropped, body);
    }
    Resp::text(200, "text/plain", body.into_bytes())
}

fn agent_push(state: &State, req: &Req) -> Resp {
    let b: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);
    let host: String = b.get("host").and_then(|x| x.as_str()).unwrap_or("").chars().take(64).collect();
    let auth = req.headers.get("authorization").map(|s| s.as_str()).unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    if host.is_empty() || !stats::check_agent_token(&state.db, &host, token) {
        return Resp::text(401, "application/json", b"{\"error\":\"unauthorized\"}".to_vec());
    }
    if let Some(arr) = b.get("lines").and_then(|x| x.as_array()) {
        let lines: Vec<String> = arr.iter().filter_map(|x| x.as_str()).map(|s| s.chars().take(2000).collect()).collect();
        if !lines.is_empty() {
            stats::store_pushed_lines(&stats_ctx(state), &host, &lines);
        }
    }
    Resp::json(200, &serde_json::json!({"ok": true, "host": host}))
}

fn admin_setup(state: &State, b: &serde_json::Value) -> Resp {
    let f = state.db.read_admin();
    let configured = f.get("user").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
        && ( !state.cfg.auth_pass_hash.is_empty() || !state.cfg.auth_password.is_empty()
            || f.get("pass_hash").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false));
    if configured {
        return Resp::json(410, &serde_json::json!({"error": "setup closed"}));
    }
    let (tok, _) = auth::setup_token(&state.db);
    let got = b.get("token").and_then(|x| x.as_str()).unwrap_or("");
    if tok.is_empty() || got != tok {
        return Resp::json(403, &serde_json::json!({"error": "bad setup token"}));
    }
    let mut user: String = b.get("user").and_then(|x| x.as_str()).unwrap_or("").trim().chars().take(64).collect();
    if user.is_empty() {
        user = "admin".to_string();
    }
    let pw = b.get("password").and_then(|x| x.as_str()).unwrap_or("");
    if pw.len() < 8 {
        return Resp::json(400, &serde_json::json!({"error": "password too short (min 8)"}));
    }
    let dir = state.db.admin_file();
    if let Some(p) = dir.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    if !state.db.write_admin(&user, &crate::crypto::mint_pass_hash(pw)) {
        return Resp::json(500, &serde_json::json!({"error": "OSError"}));
    }
    let _ = std::fs::remove_file(state.db.setup_token_file());
    state.db.activity_log(&user, "setup", "", "initial admin created");
    Resp::json(200, &serde_json::json!({"ok": true, "user": user}))
}

fn admin_password(state: &State, actor: &str, b: &serde_json::Value) -> Resp {
    if state.cfg.auth_mode != "local" {
        return Resp::json(400, &serde_json::json!({"error": "password change is local mode only"}));
    }
    // verify old: replicate verify_local_password inline
    let old = b.get("old").and_then(|x| x.as_str()).unwrap_or("");
    let new = b.get("new").and_then(|x| x.as_str()).unwrap_or("");
    let ok_old = if !state.cfg.auth_pass_hash.is_empty() {
        crate::crypto::verify_pass_hash(&state.cfg.auth_pass_hash, old)
    } else if !state.cfg.auth_password.is_empty() {
        !old.is_empty() && old == state.cfg.auth_password
    } else {
        state.db.read_admin().get("pass_hash").and_then(|x| x.as_str()).map(|h| crate::crypto::verify_pass_hash(h, old)).unwrap_or(false)
    };
    if !ok_old {
        return Resp::json(403, &serde_json::json!({"error": "old password wrong"}));
    }
    if new.len() < 8 {
        return Resp::json(400, &serde_json::json!({"error": "password too short (min 8)"}));
    }
    if !state.cfg.auth_pass_hash.is_empty() || !state.cfg.auth_password.is_empty() {
        return Resp::json(409, &serde_json::json!({"error": "env credential in use: set AUTH_PASS_HASH instead"}));
    }
    let f = state.db.read_admin();
    let user = f.get("user").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let user = if user.is_empty() {
        if state.cfg.auth_user_env.is_empty() { "admin".to_string() } else { state.cfg.auth_user_env.clone() }
    } else {
        user
    };
    if !state.db.write_admin(&user, &crate::crypto::mint_pass_hash(new)) {
        return Resp::json(500, &serde_json::json!({"error": "OSError"}));
    }
    state.db.activity_log(actor, "password", "", "admin password changed");
    Resp::json(200, &serde_json::json!({"ok": true}))
}

fn admin_reports(db: &Db) -> Vec<serde_json::Value> {
    let mut out = vec![];
    if let Ok(c) = db.open() {
        if let Ok(mut st) = c.prepare("SELECT ip, provider, ts, status, detail FROM reports ORDER BY ts DESC LIMIT 200") {
            if let Ok(rows) = st.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, f64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            }) {
                for (ip, p, t, s, d) in rows.flatten() {
                    out.push(serde_json::json!({"ip": ip, "provider": p, "ts": (t * 1000.0) as i64, "status": s, "detail": d}));
                }
            }
        }
    }
    out
}

fn enforce_config(db: &Db) -> serde_json::Value {
    let eff = Eff { db };
    let mut values = serde_json::Map::new();
    let mut locked = serde_json::Map::new();
    let mut sources = serde_json::Map::new();
    let put = |values: &mut serde_json::Map<String, serde_json::Value>, locked: &mut serde_json::Map<String, serde_json::Value>, sources: &mut serde_json::Map<String, serde_json::Value>, key: &str, env_name: &str, v: serde_json::Value| {
        values.insert(key.to_string(), v);
        locked.insert(key.to_string(), serde_json::Value::Bool(eff.locked(env_name)));
        sources.insert(key.to_string(), serde_json::Value::String(eff.source(env_name, key).to_string()));
    };
    put(&mut values, &mut locked, &mut sources, "ban_enabled", "BAN_ENABLED", serde_json::Value::Bool(eff.ban_enabled()));
    put(&mut values, &mut locked, &mut sources, "ban_jail", "BAN_JAIL", serde_json::Value::String(eff.ban_jail()));
    put(&mut values, &mut locked, &mut sources, "ban_time", "BAN_TIME", serde_json::json!(eff.ban_time()));
    put(&mut values, &mut locked, &mut sources, "ban_auto", "BAN_AUTO", serde_json::Value::Bool(eff.ban_auto()));
    put(&mut values, &mut locked, &mut sources, "ban_threshold", "BAN_THRESHOLD", serde_json::json!(eff.ban_threshold()));
    put(&mut values, &mut locked, &mut sources, "ban_window", "BAN_WINDOW", serde_json::json!(eff.ban_window()));
    put(&mut values, &mut locked, &mut sources, "ban_auto_time", "BAN_AUTO_TIME", serde_json::json!(eff.ban_auto_time()));
    put(&mut values, &mut locked, &mut sources, "report_enabled", "REPORT_ENABLED", serde_json::Value::Bool(eff.report_enabled()));
    put(&mut values, &mut locked, &mut sources, "report_provider", "REPORT_PROVIDER", serde_json::Value::String(eff.report_provider()));
    put(&mut values, &mut locked, &mut sources, "report_throttle_days", "REPORT_THROTTLE_DAYS", serde_json::json!(eff.report_throttle()));
    put(&mut values, &mut locked, &mut sources, "report_min_risk", "REPORT_MIN_RISK", serde_json::json!(eff.report_min_risk()));
    put(&mut values, &mut locked, &mut sources, "report_min_hits", "REPORT_MIN_HITS", serde_json::json!(eff.report_min_hits()));
    put(&mut values, &mut locked, &mut sources, "whitelist_ips", "WHITELIST_IPS", serde_json::Value::String(csv_of(eff.whitelist())));
    put(&mut values, &mut locked, &mut sources, "trusted_ips", "TRUSTED_IPS", serde_json::Value::String(csv_of(eff.trusted_ips())));
    put(&mut values, &mut locked, &mut sources, "trusted_users", "TRUSTED_USERS", serde_json::Value::String(csv_of(eff.trusted_users())));
    put(&mut values, &mut locked, &mut sources, "self_public_ips", "SELF_PUBLIC_IPS", serde_json::Value::String(csv_of(eff.self_extra())));
    put(&mut values, &mut locked, &mut sources, "abusers_min_hits", "ABUSERS_MIN_HITS", serde_json::json!(eff.abusers_min_hits()));
    put(&mut values, &mut locked, &mut sources, "abusers_min_score", "ABUSERS_MIN_SCORE", serde_json::json!(eff.abusers_min_score()));
    put(&mut values, &mut locked, &mut sources, "abusers_public", "ABUSERS_PUBLIC", serde_json::Value::Bool(eff.abusers_public()));
    serde_json::json!({"values": values, "locked": locked, "sources": sources})
}

fn csv_of(mut set: std::collections::HashSet<String>) -> String {
    let mut v: Vec<String> = set.drain().collect();
    v.sort();
    v.join(",")
}

fn update_config(db: &Db, b: &serde_json::Value, actor: &str) -> serde_json::Value {
    let eff = Eff { db };
    let mut updated = serde_json::Map::new();
    let mut skipped = serde_json::Map::new();
    let obj = b.as_object().cloned().unwrap_or_default();
    for (key, val) in obj.iter() {
        let env_name = match key.as_str() {
            "ban_enabled" => "BAN_ENABLED", "ban_jail" => "BAN_JAIL", "ban_time" => "BAN_TIME",
            "ban_auto" => "BAN_AUTO", "ban_threshold" => "BAN_THRESHOLD", "ban_window" => "BAN_WINDOW",
            "ban_auto_time" => "BAN_AUTO_TIME", "report_enabled" => "REPORT_ENABLED",
            "report_provider" => "REPORT_PROVIDER", "report_throttle_days" => "REPORT_THROTTLE_DAYS",
            "report_min_risk" => "REPORT_MIN_RISK", "report_min_hits" => "REPORT_MIN_HITS",
            "whitelist_ips" => "WHITELIST_IPS", "trusted_ips" => "TRUSTED_IPS",
            "trusted_users" => "TRUSTED_USERS", "self_public_ips" => "SELF_PUBLIC_IPS",
            "abusers_min_hits" => "ABUSERS_MIN_HITS", "abusers_min_score" => "ABUSERS_MIN_SCORE",
            "abusers_public" => "ABUSERS_PUBLIC", _ => continue,
        };
        if eff.locked(env_name) {
            skipped.insert(key.clone(), serde_json::Value::String("env locked".to_string()));
            continue;
        }
        let norm: Option<String> = match key.as_str() {
            "ban_enabled" | "ban_auto" | "report_enabled" | "abusers_public" => {
                Some(if is_truthy(val) { "1".to_string() } else { "0".to_string() })
            }
            "ban_time" => Some(clamp_int(val, 86400, 300, 30 * 86400).to_string()),
            "ban_threshold" => Some(clamp_int(val, 20, 3, 10000).to_string()),
            "ban_window" => Some(clamp_int(val, 600, 60, 7 * 86400).to_string()),
            "ban_auto_time" => Some(clamp_int(val, 86400, 300, 30 * 86400).to_string()),
            "report_throttle_days" => Some(clamp_int(val, 7, 1, 90).to_string()),
            "report_min_risk" => Some(clamp_int(val, 60, 0, 100).to_string()),
            "report_min_hits" => Some(clamp_int(val, 20, 2, 100000).to_string()),
            "abusers_min_hits" => Some(clamp_int(val, 5, 2, 100000).to_string()),
            "abusers_min_score" => Some(clamp_int(val, 25, 0, 100).to_string()),
            "ban_jail" => Some(clean_jail_str(val_str(val))),
            "report_provider" => {
                let s = val_str(val).to_lowercase();
                if ["abuseipdb", "webhook", "all"].contains(&s.as_str()) {
                    Some(s)
                } else {
                    skipped.insert(key.clone(), serde_json::Value::String("bad provider".to_string()));
                    None
                }
            }
            "whitelist_ips" | "trusted_ips" | "self_public_ips" => {
                let n = clean_csv_ip(&val_str(val));
                if !val_str(val).trim().is_empty() && n.is_empty() {
                    skipped.insert(key.clone(), serde_json::Value::String("no valid IPs".to_string()));
                    None
                } else {
                    Some(n)
                }
            }
            "trusted_users" => {
                let n = clean_csv_user(&val_str(val));
                if !val_str(val).trim().is_empty() && n.is_empty() {
                    skipped.insert(key.clone(), serde_json::Value::String("no valid users".to_string()));
                    None
                } else {
                    Some(n)
                }
            }
            _ => None,
        };
        if let Some(n) = norm {
            db.kv_set(&format!("cfg:{}", key), &n);
            crate::config::kv_bust();
            updated.insert(key.clone(), serde_json::Value::String(n));
        }
    }
    // refresh updated values to effective
    let cfg = enforce_config(db);
    if let Some(vals) = cfg.get("values") {
        for (k, _) in updated.clone() {
            if let Some(v) = vals.get(&k) {
                updated.insert(k, v.clone());
            }
        }
    }
    let mut keys: Vec<String> = updated.keys().cloned().collect();
    keys.sort();
    db.activity_log(actor, "config", "", &format!("enforcement update: {}", keys.join(", ").chars().take(200).collect::<String>()));
    serde_json::json!({"updated": updated, "skipped": skipped, "config": cfg})
}

fn is_truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_i64().unwrap_or(0) != 0,
        serde_json::Value::String(s) => matches!(s.trim().to_lowercase().as_str(), "1" | "yes" | "true" | "on"),
        _ => false,
    }
}

fn val_str(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn clamp_int(v: &serde_json::Value, def: i64, lo: i64, hi: i64) -> i64 {
    match v {
        serde_json::Value::Number(n) => n.as_i64().unwrap_or(def).clamp(lo, hi),
        serde_json::Value::String(s) => s.trim().parse::<i64>().map(|x| x.clamp(lo, hi)).unwrap_or(def),
        serde_json::Value::Bool(b) => if *b { 1 } else { 0 }.clamp(lo, hi),
        _ => def,
    }
}

fn clean_jail_str(s: String) -> String {
    let c: String = s.trim().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(32).collect();
    if c.is_empty() { "sshd".to_string() } else { c }
}

fn clean_csv_ip(s: &str) -> String {
    let mut out = vec![];
    for part in s.split([',', ' ', '\n', '\t']) {
        let p = part.trim();
        if p.is_empty() || out.contains(&p.to_string()) {
            continue;
        }
        if p.parse::<std::net::IpAddr>().is_ok() {
            out.push(p.to_string());
            if out.len() >= 200 {
                break;
            }
        }
    }
    out.join(",")
}

fn clean_csv_user(s: &str) -> String {
    let mut out = vec![];
    for part in s.split(',') {
        let p = part.trim();
        if p.is_empty() || out.contains(&p.to_string()) {
            continue;
        }
        if p.len() <= 64 && p.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) {
            out.push(p.to_string());
            if out.len() >= 200 {
                break;
            }
        }
    }
    out.join(",")
}

// --- serve loop ---

pub fn serve(state: std::sync::Arc<State>) {
    let port: u16 = crate::util::env("PORT", "8079").trim().parse().unwrap_or(8079).max(1);
    let server = Server::http(format!("0.0.0.0:{}", port)).expect("bind port");
    for mut request in server.incoming_requests() {
        let method = request.method().as_str().to_string();
        let url = request.url().to_string();
        let (path, query) = match url.split_once('?') {
            Some((p, q)) => (p.to_string(), parse_query(q)),
            None => (url.clone(), HashMap::new()),
        };
        let mut headers = HashMap::new();
        for h in request.headers() {
            headers.insert(h.field.as_str().to_string().to_lowercase(), h.value.as_str().to_string());
        }
        let remote = request.remote_addr().map(|a| a.ip().to_string()).unwrap_or_default();
        let mut body = vec![];
        let _ = std::io::Read::read_to_end(request.as_reader(), &mut body);
        let req = Req { method, path, query, headers, body, remote };
        let resp = handle(&state, &req);
        let mut b = tiny_http::Response::from_data(resp.body);
        b = b.with_status_code(resp.status);
        for (k, v) in resp.headers {
            if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                b = b.with_header(h);
            }
        }
        if let Ok(h) = Header::from_bytes(b"Content-Type", resp.ctype.as_bytes()) {
            b = b.with_header(h);
        }
        let _ = request.respond(b);
    }
}
