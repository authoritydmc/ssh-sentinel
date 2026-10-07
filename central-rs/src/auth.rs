//! Access control: local Basic, forward proxy headers, OIDC code flow, none.
//! Fail-closed everywhere. Mirrors central-rs gates.

use crate::config::Cfg;
use crate::db::Db;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

pub struct Gate {
    pub user: Option<String>,
    pub deny: Option<(u16, String)>,
}

// --- trusted proxies ---

fn parse_net(s: &str) -> Option<(IpAddr, u8)> {
    let (addr, bits) = s.split_once('/')?;
    let bits: u8 = bits.trim().parse().ok()?;
    Some((addr.trim().parse().ok()?, bits))
}

fn in_net(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            if bits > 32 {
                return false;
            }
            let (x, y) = (u32::from(a), u32::from(b));
            if bits == 0 {
                return true;
            }
            let m = (!0u32) << (32 - bits);
            (x & m) == (y & m)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            if bits > 128 {
                return false;
            }
            let (x, y) = (u128::from(a), u128::from(b));
            if bits == 0 {
                return true;
            }
            let m = (!0u128) << (128 - bits);
            (x & m) == (y & m)
        }
        _ => false,
    }
}

pub fn trusted_nets() -> Vec<(IpAddr, u8)> {
    let raw = crate::util::env(
        "AUTH_TRUSTED_PROXIES",
        "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10",
    );
    raw.split(',').filter_map(|p| parse_net(p.trim())).collect()
}

pub fn via_trusted_proxy(addr: &str) -> bool {
    let ip: IpAddr = match addr.split('%').next().unwrap_or("").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    trusted_nets().iter().any(|(n, b)| in_net(ip, *n, *b))
}

// --- local password ---

fn read_admin(db: &Db) -> serde_json::Value {
    db.read_admin()
}

fn effective_user(cfg: &Cfg, db: &Db) -> String {
    if !cfg.auth_user_env.is_empty() {
        return cfg.auth_user_env.clone();
    }
    read_admin(db).get("user").and_then(|x| x.as_str()).map(|s| s.to_string()).unwrap_or_else(|| "admin".to_string())
}

fn local_configured(cfg: &Cfg, db: &Db) -> bool {
    if !cfg.auth_pass_hash.is_empty() || !cfg.auth_password.is_empty() {
        return true;
    }
    let f = read_admin(db);
    f.get("user").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
        && f.get("pass_hash").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
}

fn verify_local_password(cfg: &Cfg, db: &Db, pw: &str) -> bool {
    if !cfg.auth_pass_hash.is_empty() {
        return crate::crypto::verify_pass_hash(&cfg.auth_pass_hash, pw);
    }
    if !cfg.auth_password.is_empty() {
        return !pw.is_empty() && constant_eq(pw, &cfg.auth_password);
    }
    if let Some(h) = read_admin(db).get("pass_hash").and_then(|x| x.as_str()) {
        return crate::crypto::verify_pass_hash(h, pw);
    }
    false
}

fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        d |= x ^ y;
    }
    d == 0
}

fn basic_user(cfg: &Cfg, db: &Db, headers: &HashMap<String, String>) -> String {
    let auth = headers.get("authorization").map(|s| s.as_str()).unwrap_or("");
    if !auth.starts_with("Basic ") {
        return String::new();
    }
    let raw = match base64_decode(auth[6..].trim()) {
        Some(b) => b,
        None => return String::new(),
    };
    let creds = String::from_utf8_lossy(&raw).into_owned();
    let (user, pw) = match creds.split_once(':') {
        Some(v) => v,
        None => return String::new(),
    };
    if user.is_empty() || pw.is_empty() {
        return String::new();
    }
    if user != effective_user(cfg, db) {
        return String::new();
    }
    if verify_local_password(cfg, db, pw) {
        user.to_string()
    } else {
        String::new()
    }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.decode(s).ok()
}

fn forward_user(headers: &HashMap<String, String>, names: &[String]) -> String {
    for h in names {
        if let Some(v) = headers.get(h) {
            let v = v.trim();
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    String::new()
}

fn user_allowed(cfg: &Cfg, u: &str) -> bool {
    if cfg.auth_allowed.is_empty() {
        return true;
    }
    cfg.auth_allowed.iter().any(|a| a == u || u.split('@').next().unwrap_or("") == a)
}

// --- OIDC state ---

struct Oidc {
    states: HashMap<String, (String, i64)>, // state -> (nonce, ts)
    sessions: HashMap<String, (String, i64)>, // token -> (user, exp)
    conf: (i64, serde_json::Value),
    jwks: (i64, HashMap<String, (Vec<u8>, Vec<u8>)>),
}

static OIDC: OnceLock<Mutex<Oidc>> = OnceLock::new();

fn oidc() -> &'static Mutex<Oidc> {
    OIDC.get_or_init(|| {
        Mutex::new(Oidc {
            states: HashMap::new(),
            sessions: HashMap::new(),
            conf: (0, serde_json::Value::Null),
            jwks: (0, HashMap::new()),
        })
    })
}

pub fn oidc_configured(cfg: &Cfg) -> bool {
    !(cfg.oidc_issuer.is_empty() || cfg.oidc_client.is_empty() || cfg.oidc_secret.is_empty() || cfg.oidc_redirect.is_empty())
}

fn oidc_prune() {
    let now = crate::clock_secs();
    if let Ok(mut o) = oidc().lock() {
        o.states.retain(|_, (_, ts)| now - *ts <= 600);
        o.sessions.retain(|_, (_, exp)| *exp >= now);
    }
}

fn oidc_discovery(cfg: &Cfg) -> Result<serde_json::Value, String> {
    let now = crate::clock_secs();
    if let Ok(o) = oidc().lock() {
        if o.conf.1.is_object() && now - o.conf.0 < 3600 {
            return Ok(o.conf.1.clone());
        }
    }
    let url = format!("{}/.well-known/openid-configuration", cfg.oidc_issuer);
    let t = ureq::get(&url)
        .set("User-Agent", "ssh-sentinel-oidc/1.0")
        .set("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    let conf: serde_json::Value = serde_json::from_str(&t).map_err(|e| e.to_string())?;
    for k in ["authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"] {
        if conf.get(k).and_then(|x| x.as_str()).map(|s| s.is_empty()).unwrap_or(true) {
            return Err(format!("discovery misses {}", k));
        }
    }
    if let Ok(mut o) = oidc().lock() {
        o.conf = (now, conf.clone());
    }
    Ok(conf)
}

fn oidc_keys(cfg: &Cfg) -> Result<HashMap<String, (Vec<u8>, Vec<u8>)>, String> {
    let now = crate::clock_secs();
    if let Ok(o) = oidc().lock() {
        if !o.jwks.1.is_empty() && now - o.jwks.0 < 3600 {
            return Ok(o.jwks.1.clone());
        }
    }
    let conf = oidc_discovery(cfg)?;
    let uri = conf.get("jwks_uri").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let t = ureq::get(&uri)
        .set("User-Agent", "ssh-sentinel-oidc/1.0")
        .set("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    let jwks: serde_json::Value = serde_json::from_str(&t).map_err(|e| e.to_string())?;
    let mut keys = HashMap::new();
    if let Some(arr) = jwks.get("keys").and_then(|x| x.as_array()) {
        for j in arr {
            if j.get("kty").and_then(|x| x.as_str()) != Some("RSA") {
                continue;
            }
            if j.get("use",).and_then(|x| x.as_str()).unwrap_or("sig") != "sig" {
                continue;
            }
            let (kid, n, e) = (
                j.get("kid").and_then(|x| x.as_str()).unwrap_or(""),
                j.get("n").and_then(|x| x.as_str()).unwrap_or(""),
                j.get("e").and_then(|x| x.as_str()).unwrap_or(""),
            );
            if kid.is_empty() || n.is_empty() || e.is_empty() {
                continue;
            }
            if let (Some(nb), Some(eb)) = (crate::crypto::b64url_dec(n), crate::crypto::b64url_dec(e)) {
                keys.insert(kid.to_string(), (nb, eb));
            }
        }
    }
    if keys.is_empty() {
        return Err("no RSA signing keys in JWKS".to_string());
    }
    if let Ok(mut o) = oidc().lock() {
        o.jwks = (now, keys.clone());
    }
    Ok(keys)
}

fn verify_id_token(cfg: &Cfg, token: &str, nonce: &str) -> Result<String, String> {
    let mut it = token.split('.');
    let (h_b64, p_b64, s_b64) = match (it.next(), it.next(), it.next(), it.next()) {
        (Some(a), Some(b), Some(c), None) => (a, b, c),
        _ => return Err("malformed id_token".to_string()),
    };
    let header: serde_json::Value = crate::crypto::b64url_dec(h_b64)
        .ok_or("malformed id_token encoding".to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|_| "malformed id_token encoding".to_string()))?;
    let claims: serde_json::Value = crate::crypto::b64url_dec(p_b64)
        .ok_or("malformed id_token encoding".to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|_| "malformed id_token encoding".to_string()))?;
    let sig = crate::crypto::b64url_dec(s_b64).ok_or("malformed id_token encoding".to_string())?;
    if header.get("alg").and_then(|x| x.as_str()) != Some("RS256") {
        return Err(format!("need RS256, provider sent {}", header.get("alg").map(|x| x.to_string()).unwrap_or_default()));
    }
    let keys = oidc_keys(cfg)?;
    let kid = header.get("kid").and_then(|x| x.as_str()).unwrap_or("");
    let (n, e) = keys.get(kid).or_else(|| if keys.len() == 1 { keys.values().next() } else { None }).ok_or("unknown signing key".to_string())?;
    let der = crate::crypto::rsa_der(n, e);
    let msg = format!("{}.{}", h_b64, p_b64);
    if !crate::crypto::verify_rs256(msg.as_bytes(), &sig, &der) {
        return Err("bad token signature".to_string());
    }
    let now = crate::clock_secs();
    if claims.get("exp").and_then(|x| x.as_i64()).unwrap_or(0) < now - 30 {
        return Err("token expired".to_string());
    }
    if claims.get("iat").and_then(|x| x.as_i64()).unwrap_or(0) > now + 300 {
        return Err("token issued in the future".to_string());
    }
    let conf = oidc_discovery(cfg)?;
    let iss = claims.get("iss").and_then(|x| x.as_str()).unwrap_or("").trim_end_matches('/');
    let want = conf.get("issuer").and_then(|x| x.as_str()).unwrap_or("").trim_end_matches('/');
    if iss != want {
        return Err("wrong issuer".to_string());
    }
    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(&cfg.oidc_client)),
        Some(serde_json::Value::String(s)) => s == &cfg.oidc_client,
        _ => false,
    };
    if !aud_ok {
        return Err("wrong audience".to_string());
    }
    if !nonce.is_empty() && claims.get("nonce").and_then(|x| x.as_str()).unwrap_or("") != nonce {
        return Err("wrong nonce".to_string());
    }
    let user = claims.get("email").or_else(|| claims.get("preferred_username")).or_else(|| claims.get("sub")).and_then(|x| x.as_str()).unwrap_or("").to_string();
    if user.is_empty() {
        return Err("login rejected: no identity in token".to_string());
    }
    Ok(user)
}

pub fn oidc_session_user(cookies: &HashMap<String, String>) -> String {
    let tok = cookies.get("ssh_session").map(|s| s.as_str()).unwrap_or("");
    if tok.is_empty() {
        return String::new();
    }
    let now = crate::clock_secs();
    if let Ok(mut o) = oidc().lock() {
        if let Some((u, exp)) = o.sessions.get(tok).cloned() {
            if exp >= now {
                return u;
            }
            o.sessions.remove(tok);
        }
    }
    String::new()
}

pub fn parse_cookies(header: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in header.split(';') {
        if let Some((k, v)) = part.split_once('=') {
            let k = k.trim();
            if !k.is_empty() {
                out.insert(k.to_string(), v.trim().to_string());
            }
        }
    }
    out
}

fn cookie_str(cfg: &Cfg, name: &str, value: &str, max_age: Option<i64>, clear: bool) -> String {
    let mut c = format!("{}={}; Path=/; HttpOnly; SameSite=Lax", name, value);
    if cfg.oidc_secure {
        c.push_str("; Secure");
    }
    if clear {
        c.push_str("; Max-Age=0");
    } else if let Some(a) = max_age {
        c.push_str(&format!("; Max-Age={}", a));
    }
    c
}

fn urlenc(s: &str) -> String {
    crate::geo::percent_encode(s)
}

// --- the gate ---

pub struct Req<'a> {
    pub path: &'a str,
    pub headers: &'a HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub remote: String,
}

pub fn gate(cfg: &Cfg, db: &Db, req: &Req) -> Gate {
    if cfg.auth_mode == "none" {
        return Gate { user: None, deny: None };
    }
    if cfg.auth_mode == "oidc" {
        let u = oidc_session_user(&req.cookies);
        if !u.is_empty() {
            return Gate { user: Some(u), deny: None };
        }
        if req.path.starts_with("/api/") {
            return Gate { user: None, deny: Some((401, "oidc login required".to_string())) };
        }
        return Gate { user: None, deny: Some((302, "/oidc/login".to_string())) };
    }
    if cfg.auth_mode == "forward" {
        if !via_trusted_proxy(&req.remote) {
            return Gate {
                user: None,
                deny: Some((401, "untrusted proxy: SSO identity only accepted from AUTH_TRUSTED_PROXIES".to_string())),
            };
        }
        let u = forward_user(req.headers, &cfg.fwd_headers);
        if u.is_empty() {
            return Gate {
                user: None,
                deny: Some((401, "missing SSO identity header: ForwardAuth (Authentik/Authelia) or Cloudflare Access must pass an authenticated user".to_string())),
            };
        }
        if !user_allowed(cfg, &u) {
            return Gate { user: None, deny: Some((403, "user not allowed".to_string())) };
        }
        return Gate { user: Some(u), deny: None };
    }
    let u = basic_user(cfg, db, req.headers);
    if u.is_empty() {
        if !local_configured(cfg, db) {
            return Gate {
                user: None,
                deny: Some((401, "setup needed: open Admin setup with the one-time token from DATA_DIR/setup.token or ADMIN_SETUP_TOKEN, POST /api/admin/setup — or set AUTH_USER + AUTH_PASS_HASH (`ssh-sentinel genhash`)".to_string())),
            };
        }
        return Gate { user: None, deny: Some((401, "login required".to_string())) };
    }
    Gate { user: Some(u), deny: None }
}

// --- OIDC routes ---

pub struct OidcOut {
    pub status: u16,
    pub body: String,
    pub ctype: String,
    pub headers: Vec<(String, String)>,
}

pub fn oidc_route(cfg: &Cfg, path: &str, query: &HashMap<String, String>, cookies: &HashMap<String, String>) -> OidcOut {
    oidc_prune();
    if cfg.auth_mode != "oidc" {
        return OidcOut {
            status: 404,
            body: serde_json::json!({"error": "built-in SSO is off (AUTH_MODE=oidc enables it)"}).to_string(),
            ctype: "application/json".to_string(),
            headers: vec![],
        };
    }
    if path == "/oidc/logout" {
        if let Some(tok) = cookies.get("ssh_session") {
            if let Ok(mut o) = oidc().lock() {
                o.sessions.remove(tok);
            }
        }
        return OidcOut {
            status: 302,
            body: "<a href='/'>signed out</a>".to_string(),
            ctype: "text/html".to_string(),
            headers: vec![
                ("Location".to_string(), "/".to_string()),
                ("Set-Cookie".to_string(), cookie_str(cfg, "ssh_session", "", None, true)),
            ],
        };
    }
    if path == "/oidc/login" {
        if !oidc_configured(cfg) {
            return OidcOut {
                status: 500,
                body: serde_json::json!({"error": "OIDC not configured: set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URL"}).to_string(),
                ctype: "application/json".to_string(),
                headers: vec![],
            };
        }
        let conf = match oidc_discovery(cfg) {
            Ok(c) => c,
            Err(e) => {
                return OidcOut {
                    status: 502,
                    body: serde_json::json!({"error": format!("OIDC discovery failed: {}", short_err(&e))}).to_string(),
                    ctype: "application/json".to_string(),
                    headers: vec![],
                }
            }
        };
        let state = crate::crypto::random_token_urlsafe(24);
        let nonce = crate::crypto::random_token_urlsafe(24);
        if let Ok(mut o) = oidc().lock() {
            o.states.insert(state.clone(), (nonce.clone(), crate::clock_secs()));
        }
        let dest = format!("{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&nonce={}",
            conf.get("authorization_endpoint").and_then(|x| x.as_str()).unwrap_or(""),
            urlenc(&cfg.oidc_client), urlenc(&cfg.oidc_redirect), urlenc(&cfg.oidc_scopes), urlenc(&state), urlenc(&nonce));
        return OidcOut {
            status: 302,
            body: format!("<a href='{}'>continue to SSO</a>", dest),
            ctype: "text/html".to_string(),
            headers: vec![
                ("Location".to_string(), dest),
                ("Set-Cookie".to_string(), cookie_str(cfg, "oidc_state", &state, Some(600), false)),
            ],
        };
    }
    // /oidc/callback
    let state = query.get("state").map(|s| s.as_str()).unwrap_or("");
    let code = query.get("code").map(|s| s.as_str()).unwrap_or("");
    let expect = cookies.get("oidc_state").map(|s| s.as_str()).unwrap_or("");
    let saved = if state.is_empty() {
        None
    } else if let Ok(mut o) = oidc().lock() {
        o.states.remove(state)
    } else {
        None
    };
    if state.is_empty() || code.is_empty() || saved.is_none() || state != expect {
        return OidcOut {
            status: 401,
            body: serde_json::json!({"error": "bad SSO response (state mismatch)"}).to_string(),
            ctype: "application/json".to_string(),
            headers: vec![],
        };
    }
    let (nonce, _) = saved.unwrap();
    let conf = match oidc_discovery(cfg) {
        Ok(c) => c,
        Err(e) => {
            return OidcOut {
                status: 502,
                body: serde_json::json!({"error": format!("code exchange failed: {}", short_err(&e))}).to_string(),
                ctype: "application/json".to_string(),
                headers: vec![],
            };
        }
    };
    let form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", cfg.oidc_redirect.clone()),
        ("client_id", cfg.oidc_client.clone()),
        ("client_secret", cfg.oidc_secret.clone()),
    ];
    let tok: serde_json::Value = match form_post(conf.get("token_endpoint").and_then(|x| x.as_str()).unwrap_or(""), &form) {
        Ok(v) => v,
        Err(e) => {
            return OidcOut {
                status: 502,
                body: serde_json::json!({"error": format!("code exchange failed: {}", short_err(&e))}).to_string(),
                ctype: "application/json".to_string(),
                headers: vec![],
            };
        }
    };
    let idt = tok.get("id_token").and_then(|x| x.as_str()).unwrap_or("");
    let user = match verify_id_token(cfg, idt, &nonce) {
        Ok(u) => u,
        Err(e) => {
            let msg = e.chars().take(120).collect::<String>();
            let (code, body) = if msg == "user not allowed" || e == "user not allowed" {
                (403, serde_json::json!({"error": "user not allowed"}).to_string())
            } else if msg.starts_with("login rejected") {
                (401, serde_json::json!({"error": msg}).to_string())
            } else {
                (401, serde_json::json!({"error": format!("login rejected: {}", msg)}).to_string())
            };
            return OidcOut { status: code, body, ctype: "application/json".to_string(), headers: vec![] };
        }
    };
    if !user_allowed(cfg, &user) {
        return OidcOut {
            status: 403,
            body: serde_json::json!({"error": "user not allowed"}).to_string(),
            ctype: "application/json".to_string(),
            headers: vec![],
        };
    }
    let sess = crate::crypto::random_token_urlsafe(32);
    if let Ok(mut o) = oidc().lock() {
        o.sessions.insert(sess.clone(), (user, crate::clock_secs() + cfg.oidc_ttl));
    }
    OidcOut {
        status: 302,
        body: "<a href='/'>open dashboard</a>".to_string(),
        ctype: "text/html".to_string(),
        headers: vec![
            ("Location".to_string(), "/".to_string()),
            ("Set-Cookie".to_string(), cookie_str(cfg, "ssh_session", &sess, Some(cfg.oidc_ttl), false)),
            ("Set-Cookie".to_string(), cookie_str(cfg, "oidc_state", "", None, true)),
        ],
    }
}

fn form_post(url: &str, pairs: &[(&str, String)]) -> Result<serde_json::Value, String> {
    let body: Vec<String> = pairs.iter().map(|(k, v)| format!("{}={}", urlenc(k), urlenc(v))).collect();
    ureq::post(url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .set("Accept", "application/json")
        .set("User-Agent", "rajlabs-sshlog/3.0")
        .timeout(std::time::Duration::from_secs(20))
        .send_string(&body.join("&"))
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
}

fn short_err(e: &str) -> String {
    e.split_whitespace().next().unwrap_or("Error").trim_matches(|c| c == '(' || c == ':').to_string()
}

// --- setup token + password ---

pub fn setup_token(db: &Db) -> (String, &'static str) {
    let env_tok = crate::util::env("ADMIN_SETUP_TOKEN", "").trim().to_string();
    if !env_tok.is_empty() {
        return (env_tok, "env");
    }
    if let Ok(t) = std::fs::read_to_string(db.setup_token_file()) {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return (t, "file");
        }
    }
    (String::new(), "none")
}

pub fn ensure_setup_token(cfg: &Cfg, db: &Db) -> String {
    if local_configured(cfg, db) {
        return String::new();
    }
    let env_tok = crate::util::env("ADMIN_SETUP_TOKEN", "").trim().to_string();
    if !env_tok.is_empty() {
        return env_tok;
    }
    if let Ok(t) = std::fs::read_to_string(db.setup_token_file()) {
        if !t.trim().is_empty() {
            return t.trim().to_string();
        }
    }
    let t = crate::crypto::random_token_urlsafe(24);
    let dir = db.setup_token_file();
    if let Some(p) = dir.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    if std::fs::write(db.setup_token_file(), format!("{}\n", t)).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(db.setup_token_file(), std::fs::Permissions::from_mode(0o600));
        }
        return t;
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_nets() {
        assert!(via_trusted_proxy("127.0.0.1"));
        assert!(via_trusted_proxy("10.9.9.9"));
        assert!(via_trusted_proxy("192.168.1.50"));
        assert!(via_trusted_proxy("100.100.5.5"));
        assert!(via_trusted_proxy("::1"));
        assert!(!via_trusted_proxy("8.8.8.8"));
        assert!(!via_trusted_proxy("1.1.1.1"));
        assert!(!via_trusted_proxy("not-an-ip"));
    }

    #[test]
    fn cookies() {
        let c = parse_cookies("a=1; ssh_session=tok");
        assert_eq!(c.get("ssh_session").map(|s| s.as_str()), Some("tok"));
    }
}
