//! Auth log parsing: line classes, timestamps, host store.

use chrono::{Datelike, NaiveDateTime, TimeZone};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

static OWN: OnceLock<Mutex<(i64, HashSet<String>)>> = OnceLock::new();

fn own_cell() -> &'static Mutex<(i64, HashSet<String>)> {
    OWN.get_or_init(|| Mutex::new((0, HashSet::new())))
}

pub fn own_ips(extra: &HashSet<String>) -> HashSet<String> {
    let now = crate::clock_secs();
    if let Ok(c) = own_cell().lock() {
        if !c.1.is_empty() && now - c.0 < 3600 {
            let mut merged = c.1.clone();
            drop(c);
            merged.extend(extra.iter().cloned());
            return merged;
        }
    }
    let mut found = HashSet::new();
    if let Ok(name) = hostname::get() {
        use std::net::ToSocketAddrs;
        let host = name.to_string_lossy().to_string();
        let short = host.split('.').next().unwrap_or("").to_string();
        for cand in [host, short] {
            if cand.is_empty() {
                continue;
            }
            if let Ok(addrs) = format!("{}:80", cand).to_socket_addrs() {
                for a in addrs {
                    found.insert(a.ip().to_string());
                }
            }
        }
    }
    // Default-route source address (same trick as Python).
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:80").is_ok() {
            if let Ok(a) = s.local_addr() {
                found.insert(a.ip().to_string());
            }
        }
    }
    for part in std::env::var("SELF_PUBLIC_IPS").unwrap_or_default().split(',') {
        let p = part.trim();
        if !p.is_empty() {
            found.insert(p.to_string());
        }
    }
    found.extend(extra.iter().cloned());
    if let Ok(mut c) = own_cell().lock() {
        *c = (now, found.clone());
    }
    found
}

/// Byte offsets of every occurrence of pat in ln.
fn occurrences(ln: &str, pat: &str) -> Vec<usize> {
    let mut out = vec![];
    let mut base = 0;
    let mut s = ln;
    while let Some(p) = s.find(pat) {
        out.push(base + p);
        let np = p + pat.len();
        s = &s[np..];
        base += np;
    }
    out
}

/// Strict `USER from IP`: single spaces, like `(\S+) from (\S+)`.
fn user_ip_strict(rest: &str) -> Option<(String, String)> {
    let r2 = rest.strip_prefix("invalid user ").unwrap_or(rest);
    if r2.starts_with(' ') {
        return None;
    }
    let (user, after) = r2.split_once(' ')?;
    if user.is_empty() {
        return None;
    }
    let ip_rest = after.strip_prefix("from ")?;
    if ip_rest.starts_with(' ') {
        return None;
    }
    let ip = ip_rest.split(' ').next().unwrap_or("");
    if ip.is_empty() {
        return None;
    }
    Some((user.to_string(), ip.to_string()))
}

/// (user, ip) for failed-password / invalid-user lines.
/// Single-space shapes only: `for  x` (double space) never matches,
/// same as the Python regexes.
pub fn fail_of(ln: &str) -> Option<(String, String)> {
    let mut pos = vec![];
    for pat in ["Failed password for ", "Failed publickey for "] {
        for p in occurrences(ln, pat) {
            pos.push((p, pat.len()));
        }
    }
    pos.sort();
    for (p, len) in pos {
        let rest = &ln[p + len..];
        if rest.starts_with(' ') {
            continue;
        }
        if let Some(v) = user_ip_strict(rest) {
            return Some(v);
        }
    }
    for p in occurrences(ln, "Invalid user ") {
        let rest = &ln[p + 13..];
        if rest.starts_with(' ') {
            continue;
        }
        // `Invalid user (\S+) from (\S+)`
        let (user, after) = match rest.split_once(' ') {
            Some(v) => v,
            None => continue,
        };
        if user.is_empty() {
            continue;
        }
        let ip_rest = match after.strip_prefix("from ") {
            Some(v) => v,
            None => continue,
        };
        if ip_rest.starts_with(' ') {
            continue;
        }
        let ip = ip_rest.split(' ').next().unwrap_or("");
        if ip.is_empty() {
            continue;
        }
        return Some((user.to_string(), ip.to_string()));
    }
    None
}

/// (user, ip) for accepted lines: `Accepted (password|publickey) for U from IP`.
/// No "invalid user" form exists here. Single spaces only.
pub fn accept_of(ln: &str) -> Option<(String, String)> {
    let mut pos = vec![];
    for pat in ["Accepted password for ", "Accepted publickey for "] {
        for p in occurrences(ln, pat) {
            pos.push((p, pat.len()));
        }
    }
    pos.sort();
    for (p, len) in pos {
        let rest = &ln[p + len..];
        if rest.starts_with(' ') {
            continue;
        }
        let (user, after) = match rest.split_once(' ') {
            Some(v) => v,
            None => continue,
        };
        if user.is_empty() {
            continue;
        }
        let ip_rest = match after.strip_prefix("from ") {
            Some(v) => v,
            None => continue,
        };
        if ip_rest.starts_with(' ') {
            continue;
        }
        let ip = ip_rest.split(' ').next().unwrap_or("");
        if ip.is_empty() {
            continue;
        }
        return Some((user.to_string(), ip.to_string()));
    }
    None
}

/// Tail check after an ip token: ` <ver> port <digits>`.
/// Mirrors `[0-9.]+ port \d+` with single spaces.
fn tail_port(after_ip: &str) -> bool {
    let r = match after_ip.strip_prefix(' ') {
        Some(r) => r,
        None => return false,
    };
    let (ver, r2) = match r.split_once(' ') {
        Some(v) => v,
        None => return false,
    };
    if ver.is_empty() || !ver.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return false;
    }
    let r2 = match r2.strip_prefix("port ") {
        Some(r) => r,
        None => return false,
    };
    if r2.starts_with(' ') {
        return false;
    }
    r2.bytes().next().map(|b| b.is_ascii_digit()).unwrap_or(false)
}

/// Parse `IP VER port N ...` at the start of rest. Single spaces.
fn probe_tail(rest: &str) -> Option<String> {
    let (ip, after) = rest.split_once(' ')?;
    if ip.is_empty() || !tail_port(&format!(" {}", after)) {
        return None;
    }
    Some(ip.to_string())
}

/// ip for pre-auth disconnect lines.
/// `Connection closed by IP port N` and
/// `Disconnected from [invalid user U] IP VER port N`, single spaces.
pub fn probe_ip(ln: &str) -> Option<String> {
    for p in occurrences(ln, "Connection closed by ") {
        let rest = &ln[p + 21..];
        if rest.starts_with(' ') {
            continue;
        }
        // `(\S+) port \d+`: ip token, then directly "port N".
        let (ip, after) = match rest.split_once(' ') {
            Some(v) => v,
            None => continue,
        };
        if ip.is_empty() {
            continue;
        }
        let digits = match after.strip_prefix("port ") {
            Some(v) => v,
            None => continue,
        };
        if digits.starts_with(' ') {
            continue;
        }
        if !digits.bytes().next().map(|b| b.is_ascii_digit()).unwrap_or(false) {
            continue;
        }
        if crate::util::is_public_ip(ip) {
            return Some(ip.to_string());
        }
        return None;
    }
    for p in occurrences(ln, "Disconnected from ") {
        let rest = &ln[p + 18..];
        if rest.starts_with(' ') {
            continue;
        }
        // Optional "invalid user U " prefix first (regex priority).
        if let Some(r2) = rest.strip_prefix("invalid user ") {
            if !r2.starts_with(' ') {
                if let Some((u, after_u)) = r2.split_once(' ') {
                    if !u.is_empty() {
                        if let Some(ip) = probe_tail(after_u) {
                            if crate::util::is_public_ip(&ip) {
                                return Some(ip);
                            }
                            return None;
                        }
                    }
                }
            }
            // Prefix shape failed: fall through to the no-prefix attempt,
            // like regex backtracking at the same spot.
        }
        if let Some(ip) = probe_tail(rest) {
            if crate::util::is_public_ip(&ip) {
                return Some(ip);
            }
            return None;
        }
    }
    None
}

pub fn month_num(m: &str) -> Option<u32> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Parse leading syslog or ISO timestamp. Returns local epoch millis.
pub fn parse_ts_ms(ln: &str, now: &chrono::NaiveDateTime) -> Option<i64> {
    let b = ln.as_bytes();
    if b.len() >= 16 && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' {
        // 2026-10-07T04:16:05... take YYYY-MM-DDTHH:MM
        let (y, mo, d, h, mi) = (
            ln[0..4].parse::<i32>().ok()?,
            ln[5..7].parse::<u32>().ok()?,
            ln[8..10].parse::<u32>().ok()?,
            ln[11..13].parse::<u32>().ok()?,
            ln[14..16].parse::<u32>().ok()?,
        );
        let dt = chrono::NaiveDate::from_ymd_opt(y, mo, d)?.and_hms_opt(h, mi, 0)?;
        return Some(local_ms(&dt));
    }
    // Oct  7 04:16:05
    let b = ln.as_bytes();
    if b.len() < 15 || b[3] != b' ' {
        return None;
    }
    let mon = month_num(&ln[0..3])?;
    let day: u32 = ln[4..6].trim().parse().ok()?;
    let h: u32 = ln[7..9].parse().ok()?;
    let mi: u32 = ln[10..12].parse().ok()?;
    let s: u32 = ln[13..15].parse().ok()?;
    if ln.as_bytes().get(9) != Some(&b':') || ln.as_bytes().get(12) != Some(&b':') {
        return None;
    }
    let mut dt = chrono::NaiveDate::from_ymd_opt(now.year(), mon, day)?.and_hms_opt(h, mi, s)?;
    if dt > *now + chrono::Duration::days(1) {
        dt = chrono::NaiveDate::from_ymd_opt(now.year() - 1, mon, day)?.and_hms_opt(h, mi, s)?;
    }
    Some(local_ms(&dt))
}

fn local_ms(dt: &NaiveDateTime) -> i64 {
    chrono::Local
        .from_local_datetime(dt)
        .single()
        .map(|d| d.timestamp_millis())
        .unwrap_or(0)
}

pub fn hour_ms(ms: i64) -> i64 {
    ms - (ms % 3_600_000)
}

pub fn read_lines(cfg: &crate::config::Cfg, host: Option<&str>) -> Vec<String> {
    match host {
        None => read_file(&cfg.log),
        Some(h) if h == cfg.host_id => read_file(&cfg.log),
        Some("all") => {
            let mut m = read_file(&cfg.log);
            let hdir = format!("{}/hosts", cfg.data_dir.trim_end_matches('/'));
            if let Ok(rd) = std::fs::read_dir(hdir) {
                let mut names: Vec<_> = rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
                    .collect();
                names.sort();
                for p in names {
                    m.extend(read_file(p.to_string_lossy().as_ref()));
                }
            }
            m
        }
        Some(h) => read_file(&host_path(cfg, h)),
    }
}

fn read_file(p: &str) -> Vec<String> {
    std::fs::read_to_string(p).unwrap_or_default().lines().map(|l| l.to_string()).collect()
}

fn host_path(cfg: &crate::config::Cfg, host: &str) -> String {
    let safe: String = host.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(64).collect();
    format!("{}/hosts/{}.jsonl", cfg.data_dir.trim_end_matches('/'), if safe.is_empty() { "unknown".to_string() } else { safe })
}

pub fn sanitize(ln: &str, privacy_off: bool) -> String {
    if privacy_off {
        return ln.to_string();
    }
    // Redact PWD/TTY and sudo command args (keep binary name).
    let mut s = ln.to_string();
    s = redact_after(&s, "PWD=", ' ');
    s = redact_after(&s, "TTY=", ' ');
    if let Some(i) = s.find("COMMAND=") {
        let rest = &s[i..];
        let end = rest.find(';').map(|k| i + k).unwrap_or(s.len());
        let cmd = rest[..end - i].split_whitespace().next().unwrap_or("COMMAND=").to_string();
        s = format!("{}{} <args-redacted>{}", &s[..i], cmd, &s[end..]);
    }
    s
}

fn redact_after(s: &str, key: &str, stop: char) -> String {
    let mut out = s.to_string();
    let mut from = 0;
    while let Some(i) = out[from..].find(key) {
        let a = from + i + key.len();
        let b = out[a..].find(stop).map(|k| a + k).unwrap_or(out.len());
        out.replace_range(a..b, "<redacted>");
        from = a + 10;
    }
    out
}

pub fn is_sshd_line(ln: &str, privacy_off: bool, ship_full: bool) -> bool {
    if privacy_off || ship_full {
        return true;
    }
    let l = ln.to_lowercase();
    l.contains("sshd") || l.contains("pam_unix(sshd")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_classes() {
        assert_eq!(
            fail_of("Oct 7 10:00:01 vps sshd[11]: Failed password for invalid user bob from 1.2.3.4 port 5 ssh2"),
            Some(("bob".to_string(), "1.2.3.4".to_string()))
        );
        assert_eq!(
            fail_of("Oct 7 10:00:01 vps sshd[11]: Failed password for root from 1.2.3.4 port 5 ssh2"),
            Some(("root".to_string(), "1.2.3.4".to_string()))
        );
        assert_eq!(
            fail_of("Oct 7 10:00:01 vps sshd[11]: Invalid user test from 5.6.7.8 port 1"),
            Some(("test".to_string(), "5.6.7.8".to_string()))
        );
        assert_eq!(
            accept_of("Oct 7 10:00:01 vps sshd[11]: Accepted password for ubuntu from 9.9.9.9 port 1 ssh2"),
            Some(("ubuntu".to_string(), "9.9.9.9".to_string()))
        );
        assert_eq!(
            probe_ip("Oct 7 10:00:01 vps sshd[11]: Connection closed by 77.91.71.90 port 100"),
            Some("77.91.71.90".to_string())
        );
        assert_eq!(probe_ip("Oct 7 x sudo: bob : TTY=pts/0"), None);
        // Double space after "for" never matches (same as the Python regexes).
        assert_eq!(fail_of("Oct 7 x sshd[1]: Failed password for  root from 1.2.3.4 port 5"), None);
        // Disconnect needs a version token between ip and port.
        assert_eq!(probe_ip("Oct 7 x sshd[1]: Disconnected from invalid user root 1.2.3.4 port 5"), None);
        assert_eq!(
            probe_ip("Oct 7 x sshd[1]: Disconnected from 1.2.3.4 7.4 port 5"),
            Some("1.2.3.4".to_string())
        );
        // Closed needs "port N".
        assert_eq!(probe_ip("Oct 7 x sshd[1]: Connection closed by 1.2.3.4"), None);
    }

    #[test]
    fn timestamps() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 10, 7).unwrap().and_hms_opt(12, 0, 0).unwrap();
        let ms = parse_ts_ms("Oct  7 04:16:05 vps sshd[1]: x", &now).unwrap();
        assert!(ms > 0);
        // future month rolls to last year
        let ms2 = parse_ts_ms("Dec 25 00:00:01 vps sshd[1]: x", &now).unwrap();
        assert!(ms2 < ms);
        let iso = parse_ts_ms("2026-10-07T04:16:05+00:00 x", &now).unwrap();
        assert!(iso > 0);
        assert_eq!(parse_ts_ms("no timestamp here", &now), None);
    }

    #[test]
    fn sanitize_pwd() {
        let s = sanitize("Oct 7 x sudo: bob : TTY=pts/0 ; PWD=/secret/dir ; COMMAND=/usr/bin/x args", false);
        assert!(!s.contains("/secret"));
        assert!(s.contains("/usr/bin/x <args-redacted>"));
    }
}
