//! Background loops: geo prime (600s), auto-ban and auto-report (60s).

use crate::http::State;
use crate::stats;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub fn geo_prime(state: &Arc<State>) {
    let lines = crate::logparse::read_lines(&state.cfg, None);
    let tail: Vec<&String> = lines.iter().rev().take(20000).collect();
    let mut per: HashMap<String, i64> = HashMap::new();
    for ln in tail {
        if let Some((_, ip)) = crate::logparse::fail_of(ln) {
            *per.entry(ip).or_insert(0) += 1;
        }
    }
    let mut v: Vec<(String, i64)> = per.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    let ips: Vec<String> = v.into_iter().take(60).map(|(ip, _)| ip).collect();
    // Exclude self addresses (fail lines only).
    crate::geo::geo_lookup(&ips);
}

pub fn auto_ban_scan(state: &Arc<State>) -> i64 {
    let ctx = crate::http::stats_ctx(state);
    if !ctx.eff.ban_auto() {
        return 0;
    }
    let lines = crate::logparse::read_lines(&state.cfg, None);
    let tail: Vec<&String> = lines.iter().rev().take(20000).collect();
    let now = chrono::Local::now().naive_local();
    let ban_window = ctx.eff.ban_window();
    let ban_threshold = ctx.eff.ban_threshold();
    let ban_auto_time = ctx.eff.ban_auto_time();
    let cutoff_ms = crate::clock_ms() - ban_window * 1000;
    let mut per: HashMap<String, i64> = HashMap::new();
    for ln in tail {
        let ip = crate::logparse::fail_of(ln).map(|(_, ip)| ip).or_else(|| crate::logparse::probe_ip(ln));
        let ip = match ip {
            Some(x) => x,
            None => continue,
        };
        let ets = crate::logparse::parse_ts_ms(ln, &now).unwrap_or_else(crate::clock_ms);
        if ets < cutoff_ms {
            continue;
        }
        *per.entry(ip).or_insert(0) += 1;
    }
    let mine = crate::logparse::own_ips(&ctx.eff.self_extra());
    let mut accepted = HashSet::new();
    for ln in lines.iter().rev().take(5000) {
        if let Some((_, ip)) = crate::logparse::accept_of(ln) {
            accepted.insert(ip);
        }
    }
    let active: HashSet<String> = stats::ban_list_active(&state.db)
        .into_iter()
        .filter_map(|b| b.get("ip").and_then(|x| x.as_str()).map(|s| s.to_string()))
        .collect();
    let white = ctx.eff.whitelist();
    let mut n = 0i64;
    let mut v: Vec<(String, i64)> = per.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    for (ip, hits) in v.into_iter().take(100) {
        if hits < ban_threshold {
            continue;
        }
        if active.contains(&ip) || mine.contains(&ip) || white.contains(&ip) {
            continue;
        }
        if !crate::util::is_public_ip(&ip) || accepted.contains(&ip) {
            continue;
        }
        let velocity = hits as f64 * 3600.0 / (ban_window.max(60) as f64);
        let ext = if state.cfg.abuse_key.is_empty() { 0 } else { crate::geo::abuse_score(&ip, &state.cfg.abuse_key) };
        let (score, _, _) = stats::risk_of(hits, 3, Some(crate::clock_ms()), false, ext, velocity, stats::prior_ban_flag(&state.db, &ip));
        if score < ctx.eff.abusers_min_score() {
            continue;
        }
        let r = stats::ban_add(&ctx, &ip, &format!("auto: {} fails in {}s", hits, ban_window), "auto", "system", Some(ban_auto_time));
        if r.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
            n += 1;
        }
    }
    n
}

pub fn auto_report_scan(state: &Arc<State>) -> i64 {
    let ctx = crate::http::stats_ctx(state);
    if !ctx.eff.report_enabled() {
        return 0;
    }
    let entries = stats::abusers(&ctx, None);
    let min_hits = ctx.eff.report_min_hits();
    let min_risk = ctx.eff.report_min_risk();
    let prov = ctx.eff.report_provider();
    let mut n = 0i64;
    for e in entries.iter().take(30) {
        let hits = e.get("hits").and_then(|x| x.as_i64()).unwrap_or(0);
        let risk = e.get("risk").and_then(|x| x.as_i64()).unwrap_or(0);
        if hits < min_hits || risk < min_risk {
            continue;
        }
        let ip = e.get("ip").and_then(|x| x.as_str()).unwrap_or("");
        let want: Vec<&str> = if prov == "abuseipdb" {
            vec!["abuseipdb"]
        } else if prov == "webhook" {
            vec!["webhook"]
        } else {
            vec!["abuseipdb", "webhook"]
        };
        if !want.iter().any(|p| stats::report_due(&ctx, ip, p)) {
            continue;
        }
        let band = e.get("band").and_then(|x| x.as_str()).unwrap_or("");
        let r = stats::report_ip(&ctx, ip, hits, risk, band, "system");
        if r.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
            n += 1;
        }
        if n >= 5 {
            break;
        }
    }
    n
}

pub fn ops_loop(state: Arc<State>) {
    loop {
        let _ = auto_ban_scan(&state);
        let _ = auto_report_scan(&state);
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

pub fn geo_loop(state: Arc<State>) {
    loop {
        geo_prime(&state);
        std::thread::sleep(std::time::Duration::from_secs(600));
    }
}
