//! Runtime config. Env var set (non-empty) locks the key.
//! Empty env means the Admin UI value (SQLite kv) or the default wins.

use crate::util;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Clone)]
pub struct Cfg {
    pub log: String,
    pub dist: String,
    pub data_dir: String,
    pub host_id: String,
    pub max_lines: usize,
    pub ship_full: bool,
    pub privacy_off: bool,
    pub privacy_strict: bool,
    pub auth_mode: String,
    pub auth_user: String,
    pub auth_user_env: String,
    pub auth_pass_hash: String,
    pub auth_password: String,
    pub auth_allowed: Vec<String>,
    pub fwd_headers: Vec<String>,
    pub spider: String,
    pub recon_modules: String,
    pub recon_provider: String,
    pub recon_hook: String,
    pub recon_token: String,
    pub abusers_rpm: usize,
    pub abuse_key: String,
    pub hook_url: String,
    pub hook_token: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub oidc_issuer: String,
    pub oidc_client: String,
    pub oidc_secret: String,
    pub oidc_redirect: String,
    pub oidc_scopes: String,
    pub oidc_ttl: i64,
    pub oidc_secure: bool,
    pub log_source: String,
    pub retention_days: i64,
    pub alert_url: String,
    pub alert_token: String,
    pub alert_on_success: bool,
    pub alert_spike_n: i64,
    pub alert_spike_window: i64,
    pub alert_dedupe: i64,
}

fn flag_on(v: &str) -> bool {
    matches!(v.trim().to_lowercase().as_str(), "1" | "yes" | "true" | "on")
}

fn int_env(name: &str, default: i64, lo: i64, hi: i64) -> i64 {
    util::env(name, "")
        .trim()
        .parse::<i64>()
        .map(|v| v.clamp(lo, hi))
        .unwrap_or(default)
}

fn short_host() -> String {
    hostname::get()
        .map(|h| {
            h.to_string_lossy()
                .split('.')
                .next()
                .unwrap_or("central")
                .to_string()
        })
        .unwrap_or_else(|_| "central".to_string())
}

impl Cfg {
    pub fn load(dist: String, data_dir: String) -> Cfg {
        let mode = util::env("AUTH_MODE", "local").trim().to_lowercase();
        let auth_mode = if ["local", "forward", "oidc", "none"].contains(&mode.as_str()) {
            mode
        } else {
            "local".to_string()
        };
        let privacy = util::env("PRIVACY_MODE", "balanced").trim().to_lowercase();
        let recon = util::env("RECON_PROVIDER", "spiderfoot").trim().to_lowercase();
        Cfg {
            log: util::env("AUTH_LOG", "/var/log/auth.log"),
            dist,
            data_dir,
            host_id: {
                let h = util::env("HOST_ID", "");
                if h.is_empty() { short_host() } else { h }
            },
            max_lines: int_env("MAX_LINES_PER_HOST", 60000, 1000, 10_000_000) as usize,
            ship_full: util::env("SHIP_FILTER", "sshd-only").trim().to_lowercase() == "full",
            privacy_off: privacy == "off",
            privacy_strict: privacy == "strict",
            auth_mode,
            auth_user: {
                let u = util::env("AUTH_USER", "").trim().to_string();
                if u.is_empty() { "admin".to_string() } else { u }
            },
            auth_user_env: util::env("AUTH_USER", "").trim().to_string(),
            auth_pass_hash: util::env("AUTH_PASS_HASH", "").trim().to_string(),
            auth_password: util::env("AUTH_PASSWORD", ""),
            auth_allowed: util::env("AUTH_ALLOWED_USERS", "")
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect(),
            fwd_headers: vec![
                "x-forwarded-user".to_string(),
                "x-forwarded-email".to_string(),
                "remote-user".to_string(),
                "cf-access-authenticated-user-email".to_string(),
                "x-auth-request-user".to_string(),
                "x-authentik-username".to_string(),
                "x-authentik-email".to_string(),
            ],
            spider: util::env("SPIDERFOOT_URL", "http://spiderfoot:5001").trim_end_matches('/').to_string(),
            recon_modules: util::env(
                "RECON_MODULES",
                "sfp_dnsresolve,sfp_whois,sfp_ipapico,sfp_abusech",
            ),
            recon_provider: if ["spiderfoot", "webhook", "none"].contains(&recon.as_str()) {
                recon
            } else {
                "spiderfoot".to_string()
            },
            recon_hook: util::env("RECON_WEBHOOK_URL", "").trim_end_matches('/').to_string(),
            recon_token: util::env("RECON_WEBHOOK_TOKEN", ""),
            abusers_rpm: int_env("ABUSERS_RPM", 60, 1, 100000) as usize,
            abuse_key: util::env("ABUSEIPDB_KEY", "").trim().to_string(),
            hook_url: util::env("ABUSE_WEBHOOK_URL", "").trim_end_matches('/').to_string(),
            hook_token: util::env("ABUSE_WEBHOOK_TOKEN", ""),
            tls_cert: util::env("TLS_CERT", "").trim().to_string(),
            tls_key: util::env("TLS_KEY", "").trim().to_string(),
            oidc_issuer: util::env("OIDC_ISSUER", "").trim_end_matches('/').to_string(),
            oidc_client: util::env("OIDC_CLIENT_ID", "").trim().to_string(),
            oidc_secret: util::env("OIDC_CLIENT_SECRET", ""),
            oidc_redirect: util::env("OIDC_REDIRECT_URL", "").trim().to_string(),
            oidc_scopes: {
                let s = util::env("OIDC_SCOPES", "openid email profile").trim().to_string();
                if s.is_empty() { "openid email profile".to_string() } else { s }
            },
            oidc_ttl: int_env("OIDC_SESSION_TTL", 43200, 300, 30 * 86400),
            oidc_secure: flag_on(&util::env("OIDC_COOKIE_SECURE", "")),
            log_source: util::env("LOG_SOURCE", "file").trim().to_lowercase(),
            retention_days: int_env("RETENTION_DAYS", 0, 0, 3650),
            alert_url: util::env("ALERT_WEBHOOK_URL", "").trim_end_matches('/').to_string(),
            alert_token: util::env("ALERT_WEBHOOK_TOKEN", ""),
            alert_on_success: {
                let v = util::env("ALERT_ON_SUCCESS", "");
                if v.trim().is_empty() { true } else { flag_on(&v) }
            },
            alert_spike_n: int_env("ALERT_SPIKE_THRESHOLD", 20, 2, 100000),
            alert_spike_window: int_env("ALERT_SPIKE_WINDOW_S", 300, 60, 86400),
            alert_dedupe: int_env("ALERT_DEDUPE_S", 3600, 60, 86400),
        }
    }
}

// --- effective enforcement values (env default, kv override) ---------------

static KV_CACHE: OnceLock<Mutex<(i64, HashMap<String, String>)>> = OnceLock::new();

fn kv_cache() -> &'static Mutex<(i64, HashMap<String, String>)> {
    KV_CACHE.get_or_init(|| Mutex::new((0, HashMap::new())))
}

pub fn kv_bust() {
    if let Ok(mut c) = kv_cache().lock() {
        c.0 = 0;
    }
}

fn kv_all(db: &crate::db::Db) -> HashMap<String, String> {
    let now = crate::clock_secs();
    if let Ok(c) = kv_cache().lock() {
        if now - c.0 < 5 && !c.1.is_empty() {
            return c.1.clone();
        }
    }
    let mut out = HashMap::new();
    if let Ok(conn) = db.open() {
        if let Ok(mut st) = conn.prepare("SELECT key, value FROM kv") {
            if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
                for r in rows.flatten() {
                    out.insert(r.0, r.1);
                }
            }
        }
    }
    if let Ok(mut c) = kv_cache().lock() {
        *c = (now, out.clone());
    }
    out
}

fn env_raw(name: &str) -> String {
    util::env(name, "").trim().to_string()
}

fn parse_bool_raw(v: &str, def: bool) -> bool {
    if v.trim().is_empty() {
        def
    } else {
        flag_on(v)
    }
}

fn parse_int_raw(v: &str, def: i64, lo: i64, hi: i64) -> i64 {
    v.trim().parse::<i64>().map(|x| x.clamp(lo, hi)).unwrap_or(def)
}

fn clean_jail(v: &str) -> String {
    let s: String = v.trim().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(32).collect();
    if s.is_empty() { "sshd".to_string() } else { s }
}

fn clean_provider(v: &str) -> String {
    let s = v.trim().to_lowercase();
    if ["abuseipdb", "webhook", "all"].contains(&s.as_str()) {
        s
    } else {
        "abuseipdb".to_string()
    }
}

fn clean_csv_ip(v: &str) -> String {
    let mut out = vec![];
    for part in v.split([',', ' ', '\n', '\t']) {
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

fn clean_csv_user(v: &str) -> String {
    let mut out = vec![];
    for part in v.split(',') {
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

fn eff_str(db: &crate::db::Db, env_name: &str, key: &str, clean: fn(&str) -> String) -> String {
    let raw = env_raw(env_name);
    if !raw.is_empty() {
        return clean(&raw);
    }
    let kv = kv_all(db);
    match kv.get(&format!("cfg:{}", key)) {
        Some(v) if !v.trim().is_empty() => clean(v),
        _ => String::new(),
    }
}

fn eff_bool(db: &crate::db::Db, env_name: &str, key: &str, def: bool) -> bool {
    let raw = env_raw(env_name);
    if !raw.is_empty() {
        return parse_bool_raw(&raw, def);
    }
    let kv = kv_all(db);
    match kv.get(&format!("cfg:{}", key)) {
        Some(v) if !v.trim().is_empty() => parse_bool_raw(v, def),
        _ => def,
    }
}

fn eff_int(db: &crate::db::Db, env_name: &str, key: &str, def: i64, lo: i64, hi: i64) -> i64 {
    let raw = env_raw(env_name);
    if !raw.is_empty() {
        return parse_int_raw(&raw, def, lo, hi);
    }
    let kv = kv_all(db);
    match kv.get(&format!("cfg:{}", key)) {
        Some(v) if !v.trim().is_empty() => parse_int_raw(v, def, lo, hi),
        _ => def,
    }
}

pub struct Eff<'a> {
    pub db: &'a crate::db::Db,
}

impl<'a> Eff<'a> {
    pub fn ban_enabled(&self) -> bool { eff_bool(self.db, "BAN_ENABLED", "ban_enabled", false) }
    pub fn ban_jail(&self) -> String {
        let s = eff_str(self.db, "BAN_JAIL", "ban_jail", clean_jail);
        if s.is_empty() { "sshd".to_string() } else { s }
    }
    pub fn ban_time(&self) -> i64 { eff_int(self.db, "BAN_TIME", "ban_time", 86400, 300, 30 * 86400) }
    pub fn ban_auto(&self) -> bool { eff_bool(self.db, "BAN_AUTO", "ban_auto", false) }
    pub fn ban_threshold(&self) -> i64 { eff_int(self.db, "BAN_THRESHOLD", "ban_threshold", 20, 3, 10000) }
    pub fn ban_window(&self) -> i64 { eff_int(self.db, "BAN_WINDOW", "ban_window", 600, 60, 7 * 86400) }
    pub fn ban_auto_time(&self) -> i64 { eff_int(self.db, "BAN_AUTO_TIME", "ban_auto_time", 86400, 300, 30 * 86400) }
    pub fn report_enabled(&self) -> bool { eff_bool(self.db, "REPORT_ENABLED", "report_enabled", false) }
    pub fn report_provider(&self) -> String {
        let raw = env_raw("REPORT_PROVIDER");
        if !raw.is_empty() {
            return clean_provider(&raw);
        }
        let kv = kv_all(self.db);
        match kv.get("cfg:report_provider") {
            Some(v) if !v.trim().is_empty() => clean_provider(v),
            _ => "abuseipdb".to_string(),
        }
    }
    pub fn report_throttle(&self) -> i64 { eff_int(self.db, "REPORT_THROTTLE_DAYS", "report_throttle_days", 7, 1, 90) }
    pub fn report_min_risk(&self) -> i64 { eff_int(self.db, "REPORT_MIN_RISK", "report_min_risk", 60, 0, 100) }
    pub fn report_min_hits(&self) -> i64 { eff_int(self.db, "REPORT_MIN_HITS", "report_min_hits", 20, 2, 100000) }
    pub fn whitelist(&self) -> std::collections::HashSet<String> {
        util::csv_set(&eff_str(self.db, "WHITELIST_IPS", "whitelist_ips", clean_csv_ip))
    }
    pub fn trusted_ips(&self) -> std::collections::HashSet<String> {
        let mut base = util::csv_set(&util::env("TRUSTED_IPS", ""));
        base.extend(util::csv_set(&eff_str(self.db, "TRUSTED_IPS", "trusted_ips", clean_csv_ip)));
        base
    }
    pub fn trusted_users(&self) -> std::collections::HashSet<String> {
        let mut base = util::csv_set(&util::env("TRUSTED_USERS", ""));
        base.extend(util::csv_set(&eff_str(self.db, "TRUSTED_USERS", "trusted_users", clean_csv_user)));
        base
    }
    pub fn self_extra(&self) -> std::collections::HashSet<String> {
        util::csv_set(&eff_str(self.db, "SELF_PUBLIC_IPS", "self_public_ips", clean_csv_ip))
    }
    pub fn abusers_min_hits(&self) -> i64 { eff_int(self.db, "ABUSERS_MIN_HITS", "abusers_min_hits", 5, 2, 100000) }
    pub fn abusers_min_score(&self) -> i64 { eff_int(self.db, "ABUSERS_MIN_SCORE", "abusers_min_score", 25, 0, 100) }
    pub fn abusers_public(&self) -> bool { eff_bool(self.db, "ABUSERS_PUBLIC", "abusers_public", false) }

    pub fn locked(&self, env_name: &str) -> bool {
        !env_raw(env_name).is_empty()
    }
    pub fn source(&self, env_name: &str, key: &str) -> &'static str {
        if self.locked(env_name) {
            "env"
        } else {
            let kv = kv_all(self.db);
            match kv.get(&format!("cfg:{}", key)) {
                Some(v) if !v.trim().is_empty() => "db",
                _ => "default",
            }
        }
    }
}
