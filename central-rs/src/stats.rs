//! Attack stats: risk, summary, abusers, bans, reports, alerts, host store.

use crate::config::{Cfg, Eff};
use crate::db::Db;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

// Counter is not std; small local multiset.
// Sequence numbers keep first-seen order for ties.
#[derive(Default)]
struct Bag<K: Eq + std::hash::Hash> {
    m: HashMap<K, (i64, usize)>,
    next: usize,
}
impl<K: Eq + std::hash::Hash + Clone> Bag<K> {
    fn add(&mut self, k: K, n: i64) {
        match self.m.entry(k) {
            std::collections::hash_map::Entry::Occupied(mut o) => {
                o.get_mut().0 += n;
            }
            std::collections::hash_map::Entry::Vacant(v) => {
                let seq = self.next;
                v.insert((n, seq));
                self.next += 1;
            }
        }
    }
    fn most_common(&self, n: usize) -> Vec<(K, i64)> {
        let mut v: Vec<(K, i64, usize)> =
            self.m.iter().map(|(k, (c, s))| (k.clone(), *c, *s)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)));
        v.truncate(n);
        v.into_iter().map(|(k, c, _)| (k, c)).collect()
    }
}

pub fn risk_of(hits: i64, users_n: i64, last_ms: Option<i64>, accepted: bool, external: i64, velocity: f64, prior_ban: bool) -> (i64, String, Vec<String>) {
    let mut reasons = vec![format!("{} attempts", hits)];
    let mut score = std::cmp::min(40, (12.0 * ((1 + hits) as f64).log10()) as i64);
    let ub = std::cmp::min(30, 8 * users_n);
    score += ub;
    if users_n > 1 {
        reasons.push(format!("{} users tried", users_n));
    }
    let now_ms = crate::clock_ms();
    if let Some(l) = last_ms {
        if now_ms - l < 3_600_000 {
            score += 15;
            reasons.push("active this hour".to_string());
        } else if now_ms - l < 86_400_000 {
            score += 10;
            reasons.push("active today".to_string());
        }
    }
    if velocity >= 5.0 {
        score += std::cmp::min(20, (velocity as i64) / 2);
        reasons.push(format!("fast hammer: {}/h", velocity as i64));
    }
    if prior_ban {
        score += 15;
        reasons.push("banned before".to_string());
    }
    if accepted {
        score -= 100;
        reasons.push("has a successful login (likely the owner)".to_string());
    }
    if external != 0 {
        score += std::cmp::min(25, external / 2);
        reasons.push(format!("abuse reports: {}/100", external));
    }
    score = score.clamp(0, 100);
    let band = if score < 30 { "low" } else if score < 60 { "medium" } else if score < 80 { "high" } else { "critical" };
    (score, band.to_string(), reasons)
}

pub fn classify_accept(user: &str, ip: &str, failed: &HashSet<String>, mine: &HashSet<String>, t_ips: &HashSet<String>, t_users: &HashSet<String>) -> (bool, String, bool) {
    let mut reasons = vec![];
    if failed.contains(ip) {
        reasons.push("fail-then-accept".to_string());
    }
    if !t_ips.is_empty() && !t_ips.contains(ip) && !mine.contains(ip) {
        reasons.push("unknown-ip".to_string());
    }
    if !t_users.is_empty() && !t_users.contains(user) {
        reasons.push("unknown-user".to_string());
    }
    let sus = !reasons.is_empty();
    (sus, reasons.join("+"), !sus)
}

pub struct Ctx<'a> {
    pub cfg: &'a Cfg,
    pub db: &'a Db,
    pub eff: Eff<'a>,
}

pub fn summary(ctx: &Ctx, host: Option<&str>) -> serde_json::Value {
    use crate::logparse as L;
    let lines = L::read_lines(ctx.cfg, host);
    let now = chrono::Local::now().naive_local();
    let mine = L::own_ips(&ctx.eff.self_extra());
    let white = ctx.eff.whitelist();
    let mut pairs: Bag<(String, String)> = Bag::default();
    let mut per_ip: Bag<String> = Bag::default();
    let mut hours: HashMap<i64, i64> = HashMap::new();
    let mut ok_hours: HashMap<i64, i64> = HashMap::new();
    let mut logins: Vec<(String, String, Option<i64>)> = vec![];
    let (mut skip_self, mut skip_white) = (0i64, 0i64);
    for ln in &lines {
        if let Some((u, ip)) = L::fail_of(ln) {
            if mine.contains(&ip) {
                skip_self += 1;
                continue;
            }
            if white.contains(&ip) {
                skip_white += 1;
                continue;
            }
            pairs.add((u, ip.clone()), 1);
            per_ip.add(ip, 1);
            if let Some(ts) = L::parse_ts_ms(ln, &now) {
                *hours.entry(L::hour_ms(ts)).or_insert(0) += 1;
            }
            continue;
        }
        if let Some(ip) = L::probe_ip(ln) {
            if mine.contains(&ip) {
                skip_self += 1;
                continue;
            }
            if white.contains(&ip) {
                skip_white += 1;
                continue;
            }
            pairs.add(("?".to_string(), ip.clone()), 1);
            per_ip.add(ip, 1);
            if let Some(ts) = L::parse_ts_ms(ln, &now) {
                *hours.entry(L::hour_ms(ts)).or_insert(0) += 1;
            }
            continue;
        }
        if let Some((u, ip)) = L::accept_of(ln) {
            let ts = L::parse_ts_ms(ln, &now);
            if let Some(t) = ts {
                *ok_hours.entry(L::hour_ms(t)).or_insert(0) += 1;
            }
            logins.push((u, ip, ts));
        }
    }
    let failed_ips: HashSet<String> = per_ip.m.keys().cloned().collect();
    let t_ips = ctx.eff.trusted_ips();
    let t_users = ctx.eff.trusted_users();
    let mut enriched = vec![];
    for (u, ip, ts) in &logins {
        let (sus, reason, trusted) = classify_accept(u, ip, &failed_ips, &mine, &t_ips, &t_users);
        let shown = if sus { u.clone() } else { crate::util::mask_user(u) };
        enriched.push(serde_json::json!({
            "user": shown, "user_display": shown, "ip": ip, "ts": ts,
            "suspicious": sus, "trusted": trusted, "reason": reason,
        }));
    }
    let ips: Vec<String> = per_ip.m.keys().cloned().collect();
    crate::geo::geo_lookup(&ips);
    let mut top = vec![];
    for ((u, ip), c) in pairs.most_common(25) {
        let g = crate::geo::geo_of(&ip);
        let rc = recon_cache(&ip);
        let org = g.get("org").and_then(|x| x.as_str()).unwrap_or(g.get("isp").and_then(|x| x.as_str()).unwrap_or(""));
        top.push(serde_json::json!({
            "user": u, "ip": ip, "hits": c,
            "flag": crate::util::flag(g.get("cc").and_then(|x| x.as_str()).unwrap_or("")),
            "cc": g.get("cc").and_then(|x| x.as_str()).unwrap_or(""),
            "country": g.get("country").and_then(|x| x.as_str()).unwrap_or(""),
            "city": g.get("city").and_then(|x| x.as_str()).unwrap_or(""),
            "org": org, "lat": g.get("lat"), "lon": g.get("lon"),
            "recon": {"state": rc.0, "count": rc.1},
        }));
    }
    let now_ms = crate::clock_ms();
    let base_hour = L::hour_ms(now_ms);
    let mut tl = vec![];
    // Ascending hours: now-47h .. now.
    for i in 0..48 {
        let h = base_hour - (47 - i) as i64 * 3_600_000;
        tl.push(serde_json::json!([h, hours.get(&h).copied().unwrap_or(0), ok_hours.get(&h).copied().unwrap_or(0)]));
    }
    let strict = ctx.cfg.privacy_strict;
    let mut self_ips: Vec<String> = mine.into_iter().collect();
    self_ips.sort();
    if strict {
        self_ips = self_ips.iter().map(|x| crate::util::mask_ip(x)).collect();
    }
    let sus_n = enriched.iter().filter(|e| e.get("suspicious").and_then(|x| x.as_bool()).unwrap_or(false)).count();
    let total: i64 = per_ip.m.values().map(|(c, _)| *c).sum();
    let start = enriched.len().saturating_sub(60);
    serde_json::json!({
        "total": total, "ips": per_ip.m.len(), "top": top, "timeline": tl,
        "logins": &enriched[start..],
        "suspicious_count": sus_n,
        "privacy_mode": if ctx.cfg.privacy_off { "off" } else if strict { "strict" } else { "balanced" },
        "trusted_configured": !t_ips.is_empty() || !t_users.is_empty(),
        "excluded_self": skip_self, "excluded_whitelisted": skip_white,
        "self_ips": self_ips,
        "geo_cached": crate::geo::geo_cached_count(),
        "now": now_ms, "host": host.unwrap_or("all"),
        "hosts": list_hosts(ctx),
    })
}

fn recon_cache(ip: &str) -> (String, i64) {
    // Cheap peek without network: geo module owns recon cache; expose via ip_detail? No.
    // Recon badge reads the cached recon entry when present.
    crate::geo::recon_peek(ip)
}

static ABUSERS: OnceLock<Mutex<(i64, String, Vec<serde_json::Value>)>> = OnceLock::new();

fn abusers_cell() -> &'static Mutex<(i64, String, Vec<serde_json::Value>)> {
    ABUSERS.get_or_init(|| Mutex::new((0, String::new(), vec![])))
}

pub fn abusers(ctx: &Ctx, host: Option<&str>) -> Vec<serde_json::Value> {
    use crate::logparse as L;
    let h = host.unwrap_or("all").to_string();
    let now_t = crate::clock_secs();
    if let Ok(c) = abusers_cell().lock() {
        if c.1 == h && !c.2.is_empty() && now_t - c.0 < 60 {
            return c.2.clone();
        }
    }
    let lines = L::read_lines(ctx.cfg, host);
    let now = chrono::Local::now().naive_local();
    let mine = L::own_ips(&ctx.eff.self_extra());
    let white = ctx.eff.whitelist();
    let min_hits = ctx.eff.abusers_min_hits();
    let min_score = ctx.eff.abusers_min_score();
    let mut per_ip: Bag<String> = Bag::default();
    let mut users: HashMap<String, Bag<String>> = HashMap::new();
    let mut accepted: HashSet<String> = HashSet::new();
    let mut first: HashMap<String, i64> = HashMap::new();
    let mut last: HashMap<String, i64> = HashMap::new();
    for ln in &lines {
        if let Some((_, ip)) = L::accept_of(ln) {
            accepted.insert(ip);
            continue;
        }
        let grp = L::fail_of(ln).map(|(u, ip)| (u, ip)).or_else(|| L::probe_ip(ln).map(|ip| ("?".to_string(), ip)));
        let (u, ip) = match grp {
            Some(g) => g,
            None => continue,
        };
        if mine.contains(&ip) || white.contains(&ip) || !crate::util::is_public_ip(&ip) {
            continue;
        }
        per_ip.add(ip.clone(), 1);
        users.entry(ip.clone()).or_default().add(u, 1);
        if let Some(ts) = L::parse_ts_ms(ln, &now) {
            first.entry(ip.clone()).and_modify(|e| *e = (*e).min(ts)).or_insert(ts);
            last.entry(ip.clone()).and_modify(|e| *e = (*e).max(ts)).or_insert(ts);
        }
    }
    let cands: Vec<String> = per_ip.most_common(200).into_iter().filter(|(_, h)| *h >= min_hits).map(|(ip, _)| ip).collect();
    crate::geo::geo_lookup(&cands);
    let mut ext: HashMap<String, i64> = HashMap::new();
    if !ctx.cfg.abuse_key.is_empty() {
        for ip in cands.iter().take(50) {
            ext.insert(ip.clone(), crate::geo::abuse_score(ip, &ctx.cfg.abuse_key));
        }
    }
    let mut entries = vec![];
    for (ip, hits) in per_ip.most_common(500) {
        if hits < min_hits {
            continue;
        }
        let g = crate::geo::geo_of(&ip);
        let ubag = users.get(&ip);
        let un = ubag.map(|b| b.m.len() as i64).unwrap_or(0);
        let top_users = ubag.map(|b| b.most_common(5)).unwrap_or_default();
        let (score, band, reasons) = risk_of(hits, un, last.get(&ip).copied(), accepted.contains(&ip), ext.get(&ip).copied().unwrap_or(0), 0.0, prior_ban_flag(ctx.db, &ip));
        if score < min_score || accepted.contains(&ip) {
            continue;
        }
        let org = g.get("org").and_then(|x| x.as_str()).unwrap_or(g.get("isp").and_then(|x| x.as_str()).unwrap_or(""));
        entries.push(serde_json::json!({
            "ip": ip, "hits": hits,
            "first": first.get(&ip), "last": last.get(&ip),
            "users": top_users.iter().map(|(u, c)| serde_json::json!({"user": u, "hits": c})).collect::<Vec<_>>(),
            "attempted_users": top_users.iter().map(|(u, _)| u).collect::<Vec<_>>(),
            "cc": g.get("cc").and_then(|x| x.as_str()).unwrap_or(""),
            "country": g.get("country").and_then(|x| x.as_str()).unwrap_or(""),
            "city": g.get("city").and_then(|x| x.as_str()).unwrap_or(""),
            "org": org,
            "asn": g.get("as").and_then(|x| x.as_str()).unwrap_or(""),
            "lat": g.get("lat"), "lon": g.get("lon"),
            "flag": crate::util::flag(g.get("cc").and_then(|x| x.as_str()).unwrap_or("")),
            "risk": score, "band": band, "reasons": reasons,
        }));
    }
    entries.sort_by(|a, b| {
        let (ra, ha) = (a.get("risk").and_then(|x| x.as_i64()).unwrap_or(0), a.get("hits").and_then(|x| x.as_i64()).unwrap_or(0));
        let (rb, hb) = (b.get("risk").and_then(|x| x.as_i64()).unwrap_or(0), b.get("hits").and_then(|x| x.as_i64()).unwrap_or(0));
        rb.cmp(&ra).then(hb.cmp(&ha))
    });
    if let Ok(mut c) = abusers_cell().lock() {
        *c = (now_t, h, entries.clone());
    }
    // Mirror the stats row into ip_stats.
    sync_ip_stats(ctx.db, &entries);
    entries
}

fn sync_ip_stats(db: &Db, entries: &[serde_json::Value]) {
    if let Ok(c) = db.open() {
        let now = crate::clock_secs() as f64;
        for e in entries.iter().take(200) {
            let users: Vec<String> = e.get("attempted_users").and_then(|x| x.as_array()).map(|a| a.iter().take(10).filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
            let _ = c.execute(
                "INSERT OR REPLACE INTO ip_stats(ip, hits, users_json, first, last, risk, band, reasons_json, updated) VALUES(?,?,?,?,?,?,?,?,?)",
                rusqlite::params![
                    e.get("ip").and_then(|x| x.as_str()).unwrap_or(""),
                    e.get("hits").and_then(|x| x.as_i64()).unwrap_or(0),
                    serde_json::to_string(&users).unwrap_or_default(),
                    e.get("first").and_then(|x| x.as_i64()).unwrap_or(0) as f64 / 1000.0,
                    e.get("last").and_then(|x| x.as_i64()).unwrap_or(0) as f64 / 1000.0,
                    e.get("risk").and_then(|x| x.as_i64()).unwrap_or(0),
                    e.get("band").and_then(|x| x.as_str()).unwrap_or(""),
                    serde_json::to_string(e.get("reasons").unwrap_or(&serde_json::Value::Null)).unwrap_or_default(),
                    now,
                ],
            );
        }
    }
}

pub fn ip_history(ctx: &Ctx, ip: &str, host: Option<&str>) -> serde_json::Value {
    use crate::logparse as L;
    let lines = L::read_lines(ctx.cfg, host);
    let now = chrono::Local::now().naive_local();
    let mut users: Bag<String> = Bag::default();
    let (mut hits, mut first, mut last) = (0i64, None, None);
    let mut per_hour: HashMap<i64, i64> = HashMap::new();
    for ln in &lines {
        if !ln.contains(ip) {
            continue;
        }
        if let Some((u, x)) = L::fail_of(ln) {
            if x == ip {
                users.add(u, 1);
                hits += 1;
                if let Some(ts) = L::parse_ts_ms(ln, &now) {
                    first = Some(first.map_or(ts, |f: i64| f.min(ts)));
                    last = Some(last.map_or(ts, |l: i64| l.max(ts)));
                    *per_hour.entry(L::hour_ms(ts)).or_insert(0) += 1;
                }
            }
        }
    }
    let mut tl: Vec<(i64, i64)> = per_hour.into_iter().collect();
    tl.sort();
    let tl: Vec<serde_json::Value> = tl.into_iter().rev().take(48).rev().map(|(h, c)| serde_json::json!([h, c])).collect();
    serde_json::json!({
        "users": users.most_common(10).into_iter().map(|(u, c)| serde_json::json!([u, c])).collect::<Vec<_>>(),
        "hits": hits, "first": first, "last": last, "timeline": tl,
    })
}

// --- bans ---

fn fail2ban(cmd: &str, jail: &str, ip: &str) -> bool {
    std::process::Command::new("fail2ban-client")
        .args(["set", jail, cmd, ip])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn ban_list_active(db: &Db) -> Vec<serde_json::Value> {
    let mut out = vec![];
    let now = crate::clock_secs() as f64;
    if let Ok(c) = db.open() {
        if let Ok(mut st) = c.prepare("SELECT ip, jail, reason, source, created, expires, fail2ban_ok FROM bans WHERE active=1") {
            if let Ok(rows) = st.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, f64>(4)?,
                    r.get::<_, Option<f64>>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            }) {
                for r in rows.flatten() {
                    if let Some(e) = r.5 {
                        if e < now {
                            continue;
                        }
                    }
                    out.push(serde_json::json!({
                        "ip": r.0, "jail": r.1, "reason": r.2, "source": r.3,
                        "created": (r.4 * 1000.0) as i64,
                        "expires": r.5.map(|e| (e * 1000.0) as i64),
                        "fail2ban_ok": r.6 != 0,
                    }));
                }
            }
        }
    }
    out
}

pub fn ban_add(ctx: &Ctx, ip_raw: &str, reason: &str, source: &str, actor: &str, ttl: Option<i64>) -> serde_json::Value {
    let ip = crate::util::valid_ip(ip_raw);
    if ip.is_empty() {
        return serde_json::json!({"ok": false, "error": "bad ip"});
    }
    if !crate::util::is_public_ip(&ip) {
        // valid_ip passed but reserved check: mirror "not a public IP".
        // Note valid_ip accepts any parseable; ban needs global non-reserved.
        return serde_json::json!({"ok": false, "error": "not a public IP"});
    }
    if ctx.eff.whitelist().contains(&ip) {
        return serde_json::json!({"ok": false, "error": "IP is whitelisted or self"});
    }
    {
        use crate::logparse as L;
        if L::own_ips(&ctx.eff.self_extra()).contains(&ip) {
            return serde_json::json!({"ok": false, "error": "IP is whitelisted or self"});
        }
    }
    let jail = ctx.eff.ban_jail();
    let enabled = ctx.eff.ban_enabled();
    let ttl_s = match ttl {
        None => ctx.eff.ban_time(),
        Some(t) => t.clamp(300, 30 * 86400),
    };
    let now = crate::clock_secs() as f64;
    let ok = if enabled { fail2ban("banip", &jail, &ip) } else { false };
    if let Ok(c) = ctx.db.open() {
        let _ = c.execute(
            "INSERT OR REPLACE INTO bans(ip, jail, reason, source, created, expires, active, fail2ban_ok) VALUES(?,?,?,?,?,?,1,?)",
            rusqlite::params![ip, jail, &reason.chars().take(200).collect::<String>(), &source.chars().take(20).collect::<String>(), now, now + ttl_s as f64, if ok { 1 } else { 0 }],
        );
    }
    let active: Vec<String> = ban_list_active(ctx.db).into_iter().filter_map(|b| b.get("ip").and_then(|x| x.as_str()).map(|s| s.to_string())).collect();
    ctx.db.write_banlist(&active);
    ctx.db.activity_log(actor, "ban", &ip, &format!("{} via {} f2b={}", source, jail, ok));
    serde_json::json!({"ok": true, "ip": ip, "fail2ban_ok": ok, "expires": ((now + ttl_s as f64) * 1000.0) as i64})
}

pub fn ban_remove(ctx: &Ctx, ip_raw: &str, actor: &str) -> serde_json::Value {
    let ip = crate::util::valid_ip(ip_raw);
    if ip.is_empty() {
        return serde_json::json!({"ok": false, "error": "bad ip"});
    }
    let jail = ctx.eff.ban_jail();
    let ok = if ctx.eff.ban_enabled() { fail2ban("unbanip", &jail, &ip) } else { false };
    if let Ok(c) = ctx.db.open() {
        let _ = c.execute("UPDATE bans SET active=0 WHERE ip=?", [&ip]);
    }
    let active: Vec<String> = ban_list_active(ctx.db).into_iter().filter_map(|b| b.get("ip").and_then(|x| x.as_str()).map(|s| s.to_string())).collect();
    ctx.db.write_banlist(&active);
    ctx.db.activity_log(actor, "unban", &ip, &format!("via {} f2b={}", jail, ok));
    serde_json::json!({"ok": true, "ip": ip})
}

pub fn ban_state(db: &Db, ip: &str) -> serde_json::Value {
    if let Ok(c) = db.open() {
        if let Some((source, created, expires, active)) = crate::db::ban_row_active(&c, ip) {
            if active != 0 && expires >= crate::clock_secs() as f64 {
                return serde_json::json!({"banned": true, "source": source,
                    "created": (created * 1000.0) as i64, "expires": (expires * 1000.0) as i64});
            }
        }
    }
    serde_json::json!({"banned": false})
}

pub fn prior_ban_flag(db: &Db, ip: &str) -> bool {
    if let Ok(c) = db.open() {
        if let Ok(n) = c.query_row("SELECT 1 FROM bans WHERE ip=? LIMIT 1", [ip], |r| r.get::<_, i64>(0)) {
            return n == 1;
        }
    }
    false
}

// --- reports ---

pub fn report_state(db: &Db, ip: &str) -> Vec<serde_json::Value> {
    let mut out = vec![];
    if let Ok(c) = db.open() {
        if let Ok(mut st) = c.prepare("SELECT provider, ts, status FROM reports WHERE ip=?") {
            if let Ok(rows) = st.query_map([ip], |r| Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?, r.get::<_, String>(2)?))) {
                for (p, t, s) in rows.flatten() {
                    out.push(serde_json::json!({"provider": p, "ts": (t * 1000.0) as i64, "status": s}));
                }
            }
        }
    }
    out
}

pub fn report_due(ctx: &Ctx, ip: &str, provider: &str) -> bool {
    if let Ok(c) = ctx.db.open() {
        if let Ok(ts) = c.query_row("SELECT ts FROM reports WHERE ip=? AND provider=?", rusqlite::params![ip, provider], |r| r.get::<_, f64>(0)) {
            return crate::clock_secs() as f64 - ts > ctx.eff.report_throttle() as f64 * 86400.0;
        }
    }
    true
}

fn report_record(db: &Db, ip: &str, provider: &str, status: &str, detail: &str) {
    if let Ok(c) = db.open() {
        let _ = c.execute(
            "INSERT OR REPLACE INTO reports(ip, provider, ts, status, detail) VALUES(?,?,?,?,?)",
            rusqlite::params![ip, provider, crate::clock_secs() as f64, &status.chars().take(40).collect::<String>(), &detail.chars().take(500).collect::<String>()],
        );
    }
}

pub fn report_ip(ctx: &Ctx, ip_raw: &str, hits: i64, risk: i64, band: &str, actor: &str) -> serde_json::Value {
    let ip = crate::util::valid_ip(ip_raw);
    if ip.is_empty() {
        return serde_json::json!({"ok": false, "error": "bad ip"});
    }
    if !ctx.eff.report_enabled() {
        return serde_json::json!({"ok": false, "error": "reports off"});
    }
    if hits < ctx.eff.report_min_hits() || risk < ctx.eff.report_min_risk() {
        return serde_json::json!({"ok": false, "error": "below bar"});
    }
    let prov = ctx.eff.report_provider();
    let mut providers = vec![];
    if prov == "abuseipdb" || prov == "all" {
        providers.push("abuseipdb");
    }
    if prov == "webhook" || prov == "all" {
        providers.push("webhook");
    }
    let mut out = serde_json::Map::new();
    for p in providers {
        if !report_due(ctx, &ip, p) {
            out.insert(p.to_string(), serde_json::Value::String("throttled".to_string()));
            continue;
        }
        let (ok, msg) = if p == "abuseipdb" {
            abuseipdb_report(ctx, &ip, hits, risk)
        } else {
            webhook_report(ctx, &ip, hits, risk, band)
        };
        report_record(ctx.db, &ip, p, if ok { "sent" } else { "error" }, &msg);
        ctx.db.activity_log(actor, "report", &ip, &format!("{}: {}", p, msg));
        out.insert(p.to_string(), serde_json::Value::String(msg));
    }
    serde_json::json!({"ok": true, "ip": ip, "results": out})
}

fn abuseipdb_report(ctx: &Ctx, ip: &str, hits: i64, risk: i64) -> (bool, String) {
    if ctx.cfg.abuse_key.is_empty() {
        return (false, "no key".to_string());
    }
    let fields = [("ipAddress", ip.to_string()), ("categories", "22".to_string()),
        ("comment", format!("SSH brute force: {} fails, risk {} (ssh-sentinel)", hits, risk))];
    let body: Vec<String> = fields.iter().map(|(k, v)| format!("{}={}", crate::geo::percent_encode(k), crate::geo::percent_encode(v))).collect();
    match ureq::post("https://api.abuseipdb.com/api/v2/report")
        .set("Key", &ctx.cfg.abuse_key)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .set("Accept", "application/json")
        .set("User-Agent", "ssh-sentinel/1.0")
        .timeout(std::time::Duration::from_secs(15))
        .send_string(&body.join("&"))
    {
        Ok(r) => {
            let t = r.into_string().unwrap_or_default();
            let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
            let err = v.get("errors").map(|e| e.to_string()).unwrap_or_default();
            if err.is_empty() || err == "null" {
                (true, "reported".to_string())
            } else {
                (false, err.chars().take(200).collect())
            }
        }
        Err(e) => (false, short_err(&e.to_string())),
    }
}

fn webhook_report(ctx: &Ctx, ip: &str, hits: i64, risk: i64, band: &str) -> (bool, String) {
    if ctx.cfg.hook_url.is_empty() {
        return (false, "no webhook".to_string());
    }
    let body = serde_json::json!({"ip": ip, "hits": hits, "risk": risk, "band": band,
        "categories": ["ssh-brute-force"], "source": "ssh-sentinel"}).to_string();
    let mut req = ureq::post(&ctx.cfg.hook_url)
        .set("Content-Type", "application/json")
        .set("User-Agent", "ssh-sentinel-report/1.0")
        .timeout(std::time::Duration::from_secs(15));
    if !ctx.cfg.hook_token.is_empty() {
        req = req.set("Authorization", &format!("Bearer {}", ctx.cfg.hook_token));
    }
    match req.send_string(&body) {
        Ok(r) => {
            let _ = r.into_string();
            (true, "reported".to_string())
        }
        Err(e) => (false, short_err(&e.to_string())),
    }
}

fn short_err(e: &str) -> String {
    // Mirror type(e).__name__ loosely for transport errors.
    if e.contains("status") || e.contains("Status") {
        "HTTPError".to_string()
    } else {
        e.split_whitespace().next().unwrap_or("Error").trim_matches(|c| c == '(' || c == ':').to_string()
    }
}

// --- alerts ---

static ALERT_SENT: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();

fn alert_cell() -> &'static Mutex<HashMap<String, i64>> {
    ALERT_SENT.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn alert_send(ctx: &Ctx, event: &str, payload: &serde_json::Value) -> bool {
    if ctx.cfg.alert_url.is_empty() {
        return false;
    }
    let key = format!("{}:{}:{}",
        event,
        payload.get("ip").and_then(|x| x.as_str()).unwrap_or(""),
        payload.get("user").and_then(|x| x.as_str()).unwrap_or(""));
    let now = crate::clock_secs();
    if let Ok(m) = alert_cell().lock() {
        if let Some(t) = m.get(&key) {
            if now - t < ctx.cfg.alert_dedupe {
                return false;
            }
        }
    }
    if let Ok(mut m) = alert_cell().lock() {
        m.insert(key.clone(), now);
    }
    let mut body = serde_json::json!({"event": event, "source": "ssh-sentinel", "ts": crate::clock_ms()});
    if let Some(o) = payload.as_object() {
        for (k, v) in o {
            body[k] = v.clone();
        }
    }
    let mut req = ureq::post(&ctx.cfg.alert_url)
        .set("Content-Type", "application/json")
        .set("User-Agent", "ssh-sentinel-alert/1.0")
        .timeout(std::time::Duration::from_secs(15));
    if !ctx.cfg.alert_token.is_empty() {
        req = req.set("Authorization", &format!("Bearer {}", ctx.cfg.alert_token));
    }
    match req.send_string(&body.to_string()) {
        Ok(r) => {
            let _ = r.into_string();
            ctx.db.activity_log("system", "alert", payload.get("ip").and_then(|x| x.as_str()).unwrap_or(""), event);
            true
        }
        Err(_) => {
            if let Ok(mut m) = alert_cell().lock() {
                m.remove(&key);
            }
            false
        }
    }
}

pub fn maybe_alert(ctx: &Ctx, summ: &serde_json::Value) {
    if ctx.cfg.alert_url.is_empty() {
        return;
    }
    if ctx.cfg.alert_on_success {
        if let Some(logins) = summ.get("logins").and_then(|x| x.as_array()) {
            let n = logins.len();
            for e in logins.iter().skip(n.saturating_sub(10)) {
                if e.get("suspicious").and_then(|x| x.as_bool()).unwrap_or(false) {
                    alert_send(ctx, "login.suspicious", &serde_json::json!({
                        "ip": e.get("ip"), "user": e.get("user"), "reason": e.get("reason")}));
                }
            }
        }
    }
    let now_ms = summ.get("now").and_then(|x| x.as_i64()).unwrap_or_else(crate::clock_ms);
    let win = now_ms - ctx.cfg.alert_spike_window * 1000;
    let mut recent = 0i64;
    if let Some(tl) = summ.get("timeline").and_then(|x| x.as_array()) {
        for row in tl {
            let h = row.get(0).and_then(|x| x.as_i64()).unwrap_or(0);
            let f = row.get(1).and_then(|x| x.as_i64()).unwrap_or(0);
            if h >= win {
                recent += f;
            }
        }
    }
    if recent >= ctx.cfg.alert_spike_n {
        alert_send(ctx, "spike.bruteforce", &serde_json::json!({"hits": recent, "window_s": ctx.cfg.alert_spike_window}));
    }
}

// --- host store ---

pub fn host_path(cfg: &Cfg, host: &str) -> String {
    let safe: String = host.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(64).collect();
    let s = if safe.is_empty() { "unknown".to_string() } else { safe };
    format!("{}/hosts/{}.jsonl", cfg.data_dir.trim_end_matches('/'), s)
}

pub fn store_pushed_lines(ctx: &Ctx, host: &str, lines: &[String]) {
    use crate::logparse as L;
    let _ = std::fs::create_dir_all(format!("{}/hosts", ctx.cfg.data_dir.trim_end_matches('/')));
    let p = host_path(ctx.cfg, host);
    let mut kept = vec![];
    for raw in lines.iter().take(5000) {
        let s: String = raw.chars().take(2000).collect();
        let s = s.trim_end_matches('\n').to_string();
        if !L::is_sshd_line(&s, ctx.cfg.privacy_off, ctx.cfg.ship_full) {
            continue;
        }
        kept.push(L::sanitize(&s, ctx.cfg.privacy_off));
    }
    if !kept.is_empty() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
            for ln in &kept {
                let _ = writeln!(f, "{}", ln);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
    }
    if let Ok(text) = std::fs::read_to_string(&p) {
        let mut all: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        if ctx.cfg.retention_days > 0 {
            let now_dt = chrono::Local::now().naive_local();
            let now_ms = crate::clock_ms();
            let cutoff_ms = now_ms - ctx.cfg.retention_days * 86_400_000;
            let fresh: Vec<String> = all.iter().filter(|ln| {
                L::parse_ts_ms(ln, &now_dt).map(|ms| ms >= cutoff_ms).unwrap_or(true)
            }).cloned().collect();
            // Keep fresh lines only when >=1000 lines, else the last 1000.
            all = if fresh.len() >= 1000 { fresh } else { all.into_iter().rev().take(1000).collect::<Vec<_>>().into_iter().rev().collect() };
        }
        if all.len() > ctx.cfg.max_lines {
            all = all.into_iter().rev().take(ctx.cfg.max_lines).collect::<Vec<_>>().into_iter().rev().collect();
            let _ = std::fs::write(&p, all.join("\n") + "\n");
        }
        let meta = serde_json::json!({"host": host, "last_seen": crate::clock_secs() as f64, "lines": all.len()}).to_string();
        let _ = std::fs::write(p + ".meta", meta);
    }
}

pub fn list_hosts(ctx: &Ctx) -> Vec<serde_json::Value> {
    let now = crate::clock_secs() as f64;
    let mut out = vec![serde_json::json!({"id": ctx.cfg.host_id, "local": true, "last_seen": now, "online": true})];
    let hdir = format!("{}/hosts", ctx.cfg.data_dir.trim_end_matches('/'));
    if let Ok(rd) = std::fs::read_dir(hdir) {
        let mut names: Vec<String> = vec![];
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(".jsonl") {
                names.push(name);
            }
        }
        names.sort();
        for fn_ in names {
            let id = fn_.trim_end_matches(".jsonl").to_string();
            let (mut last, mut n) = (0.0f64, 0i64);
            let mp = format!("{}/hosts/{}.meta", ctx.cfg.data_dir.trim_end_matches('/'), id);
            if let Ok(t) = std::fs::read_to_string(mp) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                    last = v.get("last_seen").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    n = v.get("lines").and_then(|x| x.as_i64()).unwrap_or(0);
                }
            }
            out.push(serde_json::json!({"id": id, "local": false, "last_seen": last, "lines": n, "online": now - last < 120.0}));
        }
    }
    out
}

pub fn check_agent_token(db: &Db, host: &str, token: &str) -> bool {
    if host.is_empty() || token.is_empty() {
        return false;
    }
    match db.agents().get(host) {
        Some(expect) => constant_time_eq(expect, token),
        None => false,
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        d |= x ^ y;
    }
    d == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_bands() {
        let (s, b, _) = risk_of(1, 1, None, false, 0, 0.0, false);
        assert!(s < 30 && b == "low");
        let (s2, b2, _) = risk_of(500, 5, Some(crate::clock_ms()), false, 0, 50.0, true);
        assert!(s2 >= 80 && b2 == "critical");
        let (s3, _, r3) = risk_of(10, 1, None, true, 0, 0.0, false);
        assert!(s3 == 0);
        assert!(r3.iter().any(|r| r.contains("successful login")));
    }

    #[test]
    fn classify_rules() {
        let mut failed = HashSet::new();
        failed.insert("1.2.3.4".to_string());
        let mine = HashSet::new();
        let mut tips = HashSet::new();
        tips.insert("9.9.9.9".to_string());
        let mut tu = HashSet::new();
        tu.insert("ubuntu".to_string());
        let (s, r, _) = classify_accept("root", "1.2.3.4", &failed, &mine, &tips, &tu);
        assert!(s && r.contains("fail-then-accept"));
        let (s2, r2, _) = classify_accept("ubuntu", "9.9.9.9", &failed, &mine, &tips, &tu);
        assert!(!s2 && r2.is_empty());
        let (s3, r3, _) = classify_accept("deploy", "5.5.5.5", &failed, &mine, &tips, &tu);
        assert!(s3 && r3.contains("unknown-ip") && r3.contains("unknown-user"));
    }
}
