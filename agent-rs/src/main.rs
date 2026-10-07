//! ssh-sentinel agent in Rust. Tails AUTH_LOG and pushes new lines.
//!
//! Protocol parity with agent-rs:
//! env names, state file shape, ship filter, push URL, headers, log text.
//! One change: a truncated file resets the offset (Python keeps stale offset).

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn short_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().split('.').next().unwrap_or("agent").to_string())
        .unwrap_or_else(|_| "agent".to_string())
}

fn keep_line(line: &str, full: bool) -> bool {
    if full {
        return true;
    }
    let l = line.to_lowercase();
    l.contains("sshd") || l.contains("pam_unix(sshd")
}

fn load_state(path: &str) -> (Option<u64>, u64) {
    let text = fs::read_to_string(path).unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    let ino = v.get("ino").and_then(|x| x.as_u64());
    let off = v.get("offset").and_then(|x| x.as_u64()).unwrap_or(0);
    (ino, off)
}

fn save_state(path: &str, ino: u64, offset: u64) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            println!("state save failed: {}", e);
            return;
        }
    }
    let body = serde_json::json!({"ino": ino, "offset": offset}).to_string();
    if let Err(e) = fs::write(path, body) {
        println!("state save failed: {}", e);
    }
}

fn read_new(log: &str, state: (Option<u64>, u64)) -> (Vec<String>, (Option<u64>, u64)) {
    let meta = match fs::metadata(log) {
        Ok(m) => m,
        Err(e) => {
            println!("log unreadable {}: {}", log, e);
            return (vec![], state);
        }
    };
    let ino = meta.ino();
    let len = meta.len();
    let mut off = if state.0 == Some(ino) { state.1 } else { 0 };
    if off > len {
        off = 0; // truncated file: start over
    }
    let mut f = match fs::File::open(log) {
        Ok(f) => f,
        Err(e) => {
            println!("log read failed: {}", e);
            return (vec![], state);
        }
    };
    if f.seek(SeekFrom::Start(off)).is_err() {
        return (vec![], state);
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return (vec![], state);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let lines: Vec<String> = text.lines().map(|l| format!("{}\n", l)).collect();
    let end = off + buf.len() as u64;
    debug_assert!(off <= len);
    (lines, (Some(ino), end))
}

fn push(central: &str, token: &str, host: &str, lines: &[String], full: bool) -> Result<(u16, String, usize, usize), String> {
    let filtered: Vec<&str> = lines.iter().map(|s| s.as_str()).filter(|l| keep_line(l, full)).collect();
    let dropped = lines.len() - filtered.len();
    let start = filtered.len().saturating_sub(2000);
    let body = serde_json::json!({"host": host, "lines": &filtered[start..]}).to_string();
    let url = format!("{}/api/agent/push", central);
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {}", token))
        .set("User-Agent", "ssh-sentinel-agent/1.0")
        .timeout(Duration::from_secs(30))
        .send_string(&body)
        .map_err(|e| format!("{}: {}", error_kind(&e), trim(&e.to_string(), 120)))?;
    let status = resp.status();
    let text = resp.into_string().unwrap_or_default();
    Ok((status, trim(&text, 200), filtered.len(), dropped))
}

fn error_kind(e: &ureq::Error) -> &'static str {
    match e {
        ureq::Error::Status(_, _) => "Status",
        ureq::Error::Transport(_) => "Transport",
    }
}

fn trim(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        println!("ssh-sentinel-agent: tails AUTH_LOG and pushes new lines to central.");
        println!("Env: CENTRAL_URL AGENT_TOKEN AGENT_ID AUTH_LOG PUSH_EVERY AGENT_STATE SHIP_FILTER.");
        return;
    }
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        println!("ssh-sentinel-agent {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let central = env("CENTRAL_URL", "http://central:8079").trim_end_matches('/').to_string();
    let token = env("AGENT_TOKEN", "");
    let host = {
        let h = env("AGENT_ID", "");
        if h.is_empty() { short_hostname() } else { h }
    };
    let log = env("AUTH_LOG", "/var/log/auth.log");
    let every: u64 = env("PUSH_EVERY", "10").parse().unwrap_or(10);
    let state_file = env("AGENT_STATE", "/var/lib/ssh-sentinel-agent/state.json");
    let full = env("SHIP_FILTER", "sshd-only").to_lowercase() == "full";
    let filter_name = if full { "full" } else { "sshd-only" };

    if token.is_empty() {
        eprintln!("AGENT_TOKEN is empty — join via central: ssh-sentinel gentoken {}", host);
        std::process::exit(1);
    }
    let mut state = load_state(&state_file);
    println!("agent {} -> {} every {}s filter={}", host, central, every, filter_name);

    let mut backoff: u64 = 5;
    loop {
        let (lines, next) = read_new(&log, state);
        if !lines.is_empty() {
            match push(&central, &token, &host, &lines, full) {
                Ok((status, body, kept, dropped)) => {
                    let extra = if dropped > 0 {
                        format!(" ({} non-sshd dropped)", dropped)
                    } else {
                        String::new()
                    };
                    let shown: String = body.chars().take(80).collect();
                    println!("pushed {}{} -> {} {}", kept, extra, status, shown);
                    state = next;
                    save_state(&state_file, next.0.unwrap_or(0), next.1);
                    backoff = 5;
                }
                Err(e) => {
                    println!("push failed ({} lines kept): {}", lines.len(), e);
                    std::thread::sleep(Duration::from_secs(backoff));
                    backoff = (backoff * 2).min(300);
                    continue;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(every));
    }
}
