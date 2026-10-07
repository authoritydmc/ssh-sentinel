//! ssh-sentinel central in Rust. Serves the UI plus JSON API on :8079.
//!
//! Commands: serve (default) | gentoken <host> | genhash [password] | scrub.

pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod geo;
pub mod http;
pub mod logparse;
pub mod ops;
pub mod stats;
pub mod util;

pub fn clock_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn clock_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn dist_dir() -> String {
    if let Ok(d) = std::env::var("DIST_DIR") {
        if !d.trim().is_empty() {
            return d;
        }
    }
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|x| x.to_string_lossy().to_string()))
        .unwrap_or_else(|| ".".to_string());
    format!("{}/dist", exe.trim_end_matches('/'))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data_dir = util::env("DATA_DIR", "./data");
    if args.len() >= 3 && args[1] == "gentoken" {
        let host: String = args[2].chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(64).collect();
        let db = db::Db::new(&data_dir);
        let mut agents = db.agents();
        let token = crypto::random_token_urlsafe(32);
        agents.insert(host.clone(), token.clone());
        let _ = std::fs::write(db.agents_file(), serde_json::to_string(&agents).unwrap_or_default());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(db.agents_file(), std::fs::Permissions::from_mode(0o600));
        }
        println!("host={}", host);
        println!("token={}", token);
        println!("central={} (tailscale URL of this host)", util::env("CENTRAL_URL", "http://<this-host>:8079"));
        return;
    }
    if args.len() >= 2 && args[1] == "genhash" {
        if args.len() >= 3 {
            println!("warning: password on the command line lands in shell history; prefer bare `genhash` for the hidden prompt.");
            let pw = args[2].clone();
            if pw.is_empty() {
                println!("empty password; aborting.");
                std::process::exit(1);
            }
            println!("AUTH_PASS_HASH={}", crypto::mint_pass_hash(&pw));
            println!("(set AUTH_USER={} + this hash; never commit either)", util::env("AUTH_USER", "admin"));
            return;
        }
        println!("genhash needs a TTY prompt; use `genhash <password>` once or mint via the running server.");
        std::process::exit(1);
    }
    if args.len() >= 2 && args[1] == "scrub" {
        scrub(&data_dir);
        return;
    }
    serve();
}

fn scrub(data_dir: &str) {
    let cfg = config::Cfg::load(dist_dir(), data_dir.to_string());
    let hdir = format!("{}/hosts", data_dir.trim_end_matches('/'));
    let (mut kept_n, mut dropped_n) = (0i64, 0i64);
    if let Ok(rd) = std::fs::read_dir(&hdir) {
        let mut names: Vec<String> = vec![];
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.ends_with(".jsonl") {
                names.push(n);
            }
        }
        names.sort();
        for fn_ in names {
            let p = format!("{}/{}", hdir, fn_);
            let src = std::fs::read_to_string(&p).unwrap_or_default();
            let lines: Vec<&str> = src.lines().collect();
            let mut kept = vec![];
            for ln in &lines {
                if logparse::is_sshd_line(ln, cfg.privacy_off, cfg.ship_full) {
                    kept.push(logparse::sanitize(ln, cfg.privacy_off));
                }
            }
            let dropped = lines.len() as i64 - kept.len() as i64;
            let tail: Vec<String> = kept.into_iter().rev().take(cfg.max_lines).collect::<Vec<_>>().into_iter().rev().collect();
            if std::fs::write(&p, tail.join("\n") + if tail.is_empty() { "" } else { "\n" }).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
                }
                let meta = serde_json::json!({"host": fn_.trim_end_matches(".jsonl"), "last_seen": clock_secs() as f64, "lines": tail.len()}).to_string();
                let _ = std::fs::write(p + ".meta", meta);
                kept_n += tail.len() as i64;
                dropped_n += dropped;
                println!("{}: kept {}, dropped {}", fn_, tail.len(), dropped);
            }
        }
    }
    println!("done: kept {}, dropped {} (mode={} filter={})",
        kept_n, dropped_n,
        if cfg.privacy_off { "off" } else { "balanced" },
        if cfg.ship_full { "full" } else { "sshd-only" });
}

fn serve() {
    let data_dir = util::env("DATA_DIR", "./data");
    let cfg = config::Cfg::load(dist_dir(), data_dir.clone());
    let db = db::Db::new(&data_dir);
    db.init();
    let state = std::sync::Arc::new(http::State {
        cfg: cfg.clone(),
        db,
        start_ms: clock_ms(),
        abusers_hits: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    if cfg.auth_mode == "local" {
        let f = state.db.read_admin();
        let ok = !cfg.auth_pass_hash.is_empty() || !cfg.auth_password.is_empty()
            || (f.get("user").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                && f.get("pass_hash").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false));
        if !ok {
            let tok = auth::ensure_setup_token(&cfg, &state.db);
            println!("auth: MODE=local setup needed — open Admin setup with one-time token");
            println!("auth: token source={} (file {} or ADMIN_SETUP_TOKEN)",
                if util::env("ADMIN_SETUP_TOKEN", "").trim().is_empty() { "file" } else { "env" },
                state.db.setup_token_file().to_string_lossy());
            if tok.is_empty() {
                println!("auth: setup token missing — set ADMIN_SETUP_TOKEN");
            }
        }
    }
    {
        let s = state.clone();
        std::thread::spawn(move || ops::geo_loop(s));
    }
    {
        let s = state.clone();
        std::thread::spawn(move || ops::ops_loop(s));
    }
    ops::geo_prime(&state);
    let eff = config::Eff { db: &state.db };
    println!("ops: bans auto={} threshold={}/{}s jail={} reports={} provider={}",
        eff.ban_auto(), eff.ban_threshold(), eff.ban_window(), eff.ban_jail(),
        eff.report_enabled(), eff.report_provider());
    if cfg.auth_mode == "none" {
        println!("auth: MODE=none (open) — keep 8079 on tailnet/localhost or behind SSO; set AUTH_MODE=local|forward for login");
    } else if cfg.auth_mode == "forward" {
        println!("auth: MODE=forward (ForwardAuth/OIDC via X-Forwarded-User,X-Forwarded-Email, proxies trusted)");
    } else if cfg.auth_mode == "oidc" {
        println!("auth: MODE=oidc issuer={} creds={}", if cfg.oidc_issuer.is_empty() { "MISSING" } else { &cfg.oidc_issuer },
            if auth::oidc_configured(&cfg) { "configured" } else { "MISSING (login disabled)" });
    } else {
        println!("auth: MODE=local creds={}", if state.db.read_admin().get("user").is_some() || !cfg.auth_pass_hash.is_empty() { "configured" } else { "MISSING (deny-all)" });
    }
    if !cfg.tls_cert.is_empty() && !cfg.tls_key.is_empty() {
        println!("tls: in-repo TLS is not supported by this build; terminate at Tailscale/Traefik (WARN: TLS_CERT is set)");
    }
    http::serve(state);
}
