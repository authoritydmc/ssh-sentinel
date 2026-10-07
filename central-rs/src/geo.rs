//! Enrichment: geo (ip-api), RDAP, rDNS, abuse score, recon.
//! In-memory cache plus best-effort /tmp file persistence.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const UA: &str = "rajlabs-sshlog/3.0";
const GEO_CACHE: &str = "/tmp/sshlog_geo.json";
const IP_CACHE: &str = "/tmp/sshlog_ipcache.json";
const IP_TTL: i64 = 7 * 86400;
const RECON_TTL: i64 = 7 * 86400;
const ABUSE_TTL: i64 = 24 * 3600;
const RECON_INTERESTING: &[&str] = &[
    "GEOINFO", "DOMAIN_NAME", "INTERNET_NAME", "AFFILIATE_DOMAIN_NAME",
    "BGP_AS_MEMBER", "BGP_AS_OWNER", "NETBLOCK_MEMBER", "NETBLOCK_OWNER",
    "AFFILIATE_IPADDR", "IP_ADDRESS", "RAW_RIR_DATA", "ABUSECH_MALWARE",
    "BLACKLISTED_IPADDR", "TOR_EXIT_NODE", "PROXY_HOST",
];

struct State {
    geo: HashMap<String, (i64, serde_json::Value)>,
    ip: HashMap<String, serde_json::Value>,
    recon: HashMap<String, serde_json::Value>,
    abuse: HashMap<String, (i64, i64)>,
    loaded: bool,
}

static ST: OnceLock<Mutex<State>> = OnceLock::new();

fn st() -> &'static Mutex<State> {
    ST.get_or_init(|| {
        Mutex::new(State {
            geo: HashMap::new(),
            ip: HashMap::new(),
            recon: HashMap::new(),
            abuse: HashMap::new(),
            loaded: false,
        })
    })
}

fn load_files() {
    let mut s = match st().lock() {
        Ok(s) => s,
        Err(_) => return,
    };
    if s.loaded {
        return;
    }
    s.loaded = true;
    if let Ok(t) = std::fs::read_to_string(GEO_CACHE) {
        if let Ok(m) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&t) {
            for (k, v) in m {
                if k.starts_with("geo:") {
                    let ts = v.get("ts").and_then(|x| x.as_i64()).unwrap_or(0);
                    s.geo.insert(k, (ts, v));
                }
            }
        }
    }
    if let Ok(t) = std::fs::read_to_string(IP_CACHE) {
        if let Ok(m) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&t) {
            for (k, v) in m {
                if k.starts_with("ip:") {
                    s.ip.insert(k, v);
                }
            }
        }
    }
}

fn save_files() {
    let snapshot: Option<(HashMap<String, serde_json::Value>, HashMap<String, serde_json::Value>)> =
        st().lock().ok().map(|s| {
            let mut g = HashMap::new();
            for (k, (_, v)) in s.geo.iter() {
                g.insert(k.clone(), v.clone());
            }
            let mut p = HashMap::new();
            for (k, v) in s.ip.iter() {
                p.insert(k.clone(), v.clone());
            }
            (g, p)
        });
    if let Some((g, p)) = snapshot {
        let _ = std::fs::write(GEO_CACHE, serde_json::to_string(&g).unwrap_or_default());
        let _ = std::fs::write(IP_CACHE, serde_json::to_string(&p).unwrap_or_default());
    }
}

fn http_get(url: &str, ua: &str, timeout: u64) -> Result<String, String> {
    ureq::get(url)
        .set("User-Agent", ua)
        .set("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(timeout))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())
}

pub fn geo_lookup(ips: &[String]) {
    load_files();
    let missing: Vec<String> = {
        let s = st().lock().unwrap();
        ips.iter().collect::<std::collections::HashSet<_>>().into_iter().filter(|ip| {
            !s.geo.contains_key(&format!("geo:{}", ip)) && crate::util::is_public_ip(ip)
        }).map(|x| x.clone()).collect()
    };
    if missing.is_empty() {
        return;
    }
    let batch: Vec<serde_json::Value> = missing.iter().take(100).map(|ip| serde_json::json!({"query": ip})).collect();
    let body = serde_json::to_string(&batch).unwrap_or_default();
    let url = "http://ip-api.com/batch?fields=query,status,country,countryCode,city,org,as,isp,hosting,proxy,lat,lon";
    let res = ureq::post(url)
        .set("Content-Type", "application/json")
        .set("User-Agent", UA)
        .timeout(std::time::Duration::from_secs(15))
        .send_string(&body);
    if let Ok(r) = res {
        if let Ok(arr) = r.into_string().map(|t| serde_json::from_str::<Vec<serde_json::Value>>(&t).unwrap_or_default()) {
            let now = crate::clock_secs();
            if let Ok(mut s) = st().lock() {
                for row in arr {
                    if row.get("status").and_then(|x| x.as_str()) != Some("success") {
                        continue;
                    }
                    let q = row.get("query").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let v = serde_json::json!({
                        "country": row.get("country").and_then(|x| x.as_str()).unwrap_or(""),
                        "cc": row.get("countryCode").and_then(|x| x.as_str()).unwrap_or(""),
                        "city": row.get("city").and_then(|x| x.as_str()).unwrap_or(""),
                        "org": row.get("org").and_then(|x| x.as_str()).unwrap_or(""),
                        "as": row.get("as").and_then(|x| x.as_str()).unwrap_or(""),
                        "isp": row.get("isp").and_then(|x| x.as_str()).unwrap_or(""),
                        "lat": row.get("lat"), "lon": row.get("lon"),
                        "hosting": row.get("hosting").and_then(|x| x.as_bool()).unwrap_or(false),
                        "proxy": row.get("proxy").and_then(|x| x.as_bool()).unwrap_or(false),
                        "ts": now,
                    });
                    s.geo.insert(format!("geo:{}", q), (now, v));
                }
            }
            save_files();
        }
    }
}

pub fn geo_of(ip: &str) -> serde_json::Value {
    load_files();
    st().lock().ok().and_then(|s| s.geo.get(&format!("geo:{}", ip)).map(|(_, v)| v.clone())).unwrap_or(serde_json::json!({}))
}

pub fn geo_cached_count() -> usize {
    st().lock().map(|s| s.geo.len()).unwrap_or(0)
}

/// Peek cached recon entry without network: (state, count if done else 0).
pub fn recon_peek(ip: &str) -> (String, i64) {
    load_files();
    if let Ok(s) = st().lock() {
        if let Some(v) = s.recon.get(&format!("recon:{}", ip)) {
            let state = v.get("state").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let done = v.get("done").and_then(|x| x.as_bool()).unwrap_or(false);
            let count = if done { v.get("count").and_then(|x| x.as_i64()).unwrap_or(0) } else { 0 };
            return (state, count);
        }
    }
    (String::new(), 0)
}

fn ptr_of(ip: &str) -> String {
    // getent exists on glibc hosts (Debian/Ubuntu). Empty string on failure.
    match std::process::Command::new("getent").arg("hosts").arg(ip).output() {
        Ok(o) if o.status.success() => {
            let t = String::from_utf8_lossy(&o.stdout);
            let mut it = t.split_whitespace();
            it.next();
            it.next().unwrap_or("").to_string()
        }
        _ => String::new(),
    }
}

pub fn ip_detail(ip: &str) -> serde_json::Value {
    if !crate::util::is_public_ip(ip) {
        return serde_json::json!({"ip": ip, "private": true});
    }
    load_files();
    let now = crate::clock_secs();
    if let Ok(s) = st().lock() {
        if let Some(v) = s.ip.get(&format!("ip:{}", ip)) {
            let ts = v.get("ts").and_then(|x| x.as_i64()).unwrap_or(0);
            if now - ts < IP_TTL && v.get("done").and_then(|x| x.as_bool()).unwrap_or(false) {
                return v.clone();
            }
        }
    }
    geo_lookup(&[ip.to_string()]);
    let g = geo_of(ip);
    let ptr = ptr_of(ip);
    let mut d = serde_json::json!({"ip": ip, "ts": now, "done": true});
    for k in ["country", "cc", "city", "org", "isp", "as", "lat", "lon"] {
        if let Some(v) = g.get(k) {
            d[k] = v.clone();
        }
    }
    d["ptr"] = serde_json::Value::String(ptr);
    match http_get(&format!("https://rdap.org/ip/{}", ip), UA, 10) {
        Ok(t) => {
            if let Ok(r) = serde_json::from_str::<serde_json::Value>(&t) {
                d["rdap_name"] = r.get("name").cloned().unwrap_or_default();
                d["rdap_handle"] = r.get("handle").cloned().unwrap_or_default();
                d["rdap_cc"] = r.get("country").cloned().unwrap_or_default();
                let ents: Vec<serde_json::Value> = r.get("entities").and_then(|x| x.as_array()).map(|a| {
                    a.iter().take(5).map(|e| e.get("handle").cloned().unwrap_or_default()).collect()
                }).unwrap_or_default();
                d["rdap_entities"] = serde_json::Value::Array(ents);
                let upd = r.get("events").and_then(|x| x.as_array()).and_then(|a| a.last()).and_then(|e| e.get("eventDate")).and_then(|x| x.as_str()).map(|s| s.chars().take(10).collect::<String>()).unwrap_or_default();
                d["rdap_updated"] = serde_json::Value::String(upd);
            }
        }
        Err(e) => {
            d["rdap_error"] = serde_json::Value::String(short_kind(&e));
        }
    }
    if let Ok(mut s) = st().lock() {
        s.ip.insert(format!("ip:{}", ip), d.clone());
    }
    save_files();
    d
}

fn short_kind(e: &str) -> String {
    // Map transport text to short error names.
    if e.contains("status") || e.contains("Status") {
        "HTTPError".to_string()
    } else {
        "URLError".to_string()
    }
}

pub fn abuse_score(ip: &str, key: &str) -> i64 {
    if key.is_empty() {
        return 0;
    }
    let now = crate::clock_secs();
    if let Ok(s) = st().lock() {
        if let Some((ts, v)) = s.abuse.get(ip) {
            if now - ts < ABUSE_TTL {
                return *v;
            }
        }
    }
    let mut score = 0i64;
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90", ip);
    if let Ok(r) = ureq::get(&url)
        .set("Key", key)
        .set("Accept", "application/json")
        .set("User-Agent", "ssh-sentinel/1.0")
        .timeout(std::time::Duration::from_secs(10))
        .call()
    {
        if let Ok(t) = r.into_string() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                score = v.get("data").and_then(|d| d.get("abuseConfidenceScore")).and_then(|x| x.as_i64()).unwrap_or(0).clamp(0, 100);
            }
        }
    }
    if let Ok(mut s) = st().lock() {
        s.abuse.insert(ip.to_string(), (now, score));
    }
    score
}

pub fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn spider(spider_base: &str, path: &str, form: Option<Vec<(&str, String)>>, timeout: u64) -> Result<serde_json::Value, String> {
    let url = format!("{}{}", spider_base, path);
    if let Some(pairs) = form {
        let body: Vec<String> = pairs.iter().map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v))).collect();
        ureq::post(&url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .set("Accept", "application/json")
            .set("User-Agent", "rajlabs-sshlog/3.0")
            .timeout(std::time::Duration::from_secs(timeout))
            .send_string(&body.join("&"))
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
    } else {
        ureq::get(&url)
            .set("User-Agent", "rajlabs-sshlog/3.0")
            .timeout(std::time::Duration::from_secs(timeout))
            .call()
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
    }
}

pub fn recon_status(ip: &str, force: bool, spider_base: &str, modules: &str, provider: &str, hook: &str, hook_token: &str) -> serde_json::Value {
    load_files();
    let key = format!("recon:{}", ip);
    let now = crate::clock_secs();
    if !force {
        if let Ok(s) = st().lock() {
            if let Some(v) = s.recon.get(&key) {
                let done = v.get("done").and_then(|x| x.as_bool()).unwrap_or(false);
                let ts = v.get("ts").and_then(|x| x.as_i64()).unwrap_or(0);
                if done && now - ts < RECON_TTL {
                    let mut c = v.clone();
                    c["state"] = serde_json::Value::String("cached".to_string());
                    return c;
                }
            }
        }
    }
    if provider == "none" {
        return serde_json::json!({"state": "done", "scan": "disabled", "status": "DISABLED",
            "done": false, "ts": now, "count": 0, "results": []});
    }
    if provider == "webhook" {
        return recon_webhook(&key, ip, hook, hook_token, now);
    }
    let scans = match spider(spider_base, "/scanlist", None, 15) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({"state": "error", "error": format!(
                "spiderfoot unreachable at {} ({}): start it with docker compose --profile recon up -d --build",
                spider_base, short_kind(&e))});
        }
    };
    let mut sid: Option<String> = None;
    if !force {
        if let Ok(s) = st().lock() {
            if let Some(v) = s.recon.get(&key) {
                sid = v.get("scan").and_then(|x| x.as_str()).map(|x| x.to_string());
            }
        }
    }
    if sid.is_none() {
        if let Some(arr) = scans.as_array() {
            for row in arr {
                let r = row.as_array().cloned().unwrap_or_default();
                if r.len() > 6
                    && r[2].as_str() == Some(ip)
                    && r[1].as_str().map(|n| n.starts_with("sshlog:")).unwrap_or(false)
                {
                    sid = r[0].as_str().map(|x| x.to_string());
                    break;
                }
            }
        }
    }
    if sid.is_none() || force {
        let r = spider(spider_base, "/startscan", Some(vec![
            ("scanname", format!("sshlog:{}", ip)),
            ("scantarget", ip.to_string()),
            ("modulelist", modules.to_string()),
            ("typelist", "IP_ADDRESS".to_string()),
            ("usecase", "all".to_string()),
        ]), 30);
        match r {
            Ok(v) => {
                let arr = v.as_array().cloned().unwrap_or_default();
                let ok = arr.first().and_then(|x| x.as_str()) == Some("SUCCESS");
                let id = arr.get(1).and_then(|x| x.as_str()).map(|x| x.to_string());
                match (ok, id) {
                    (true, Some(id)) => {
                        let d = serde_json::json!({"state": "started", "scan": id, "done": false, "ts": now});
                        if let Ok(mut s) = st().lock() {
                            s.recon.insert(key, d.clone());
                        }
                        return d;
                    }
                    _ => return serde_json::json!({"state": "error", "error": format!("startscan rejected: {}", trim(&v.to_string(), 120))}),
                }
            }
            Err(e) => return serde_json::json!({"state": "error", "error": format!("startscan failed: {}", short_kind(&e))}),
        }
    }
    let sid = sid.unwrap();
    let status = match spider(spider_base, &format!("/scanstatus?id={}", sid), None, 15) {
        Ok(v) => v.as_array().and_then(|a| a.get(5)).and_then(|x| x.as_str()).unwrap_or("?").to_string(),
        Err(e) => return serde_json::json!({"state": "error", "error": format!("scanstatus failed: {}", short_kind(&e)), "scan": sid}),
    };
    if !["FINISHED", "ERROR-FAILED", "ABORTED"].contains(&status.as_str()) {
        return serde_json::json!({"state": "running", "scan": sid, "status": status});
    }
    let rows = match spider(spider_base, &format!("/scaneventresults?id={}&eventType=ALL", sid), None, 30) {
        Ok(v) => v,
        Err(e) => return serde_json::json!({"state": "error", "error": format!("results fetch failed: {}", short_kind(&e)), "scan": sid}),
    };
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<serde_json::Value> = vec![];
    let base = ip_detail(ip);
    if base.get("city").and_then(|x| x.as_str()).map(|x| !x.is_empty()).unwrap_or(false)
        || base.get("country").and_then(|x| x.as_str()).map(|x| !x.is_empty()).unwrap_or(false)
    {
        let loc = [base.get("city"), base.get("country")].into_iter().flatten().filter_map(|x| x.as_str()).filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", ");
        push_finding(&mut seen, &mut out, "GEOINFO", &loc, "sshlog:geoip");
    }
    let org = base.get("org").and_then(|x| x.as_str()).unwrap_or(base.get("isp").and_then(|x| x.as_str()).unwrap_or(""));
    push_finding(&mut seen, &mut out, "ORG", org, "sshlog:geoip");
    push_finding(&mut seen, &mut out, "ASN", base.get("as").and_then(|x| x.as_str()).unwrap_or(""), "sshlog:geoip");
    push_finding(&mut seen, &mut out, "DOMAIN_NAME", base.get("ptr").and_then(|x| x.as_str()).unwrap_or(""), "sshlog:rdns");
    if base.get("rdap_name").and_then(|x| x.as_str()).map(|x| !x.is_empty()).unwrap_or(false)
        || base.get("rdap_handle").and_then(|x| x.as_str()).map(|x| !x.is_empty()).unwrap_or(false)
    {
        push_finding(&mut seen, &mut out, "NETBLOCK_OWNER", &format!("{} {} {}", base.get("rdap_name").and_then(|x| x.as_str()).unwrap_or(""), base.get("rdap_handle").and_then(|x| x.as_str()).unwrap_or(""), base.get("rdap_cc").and_then(|x| x.as_str()).unwrap_or("")), "sshlog:rdap");
    }
    if let Some(arr) = rows.as_array() {
        for r in arr {
            let row = r.as_array().cloned().unwrap_or_default();
            if row.len() < 8 {
                continue;
            }
            let (typ, data, modu) = (
                row[7].as_str().unwrap_or("").to_string(),
                row[1].as_str().unwrap_or("").to_string(),
                row[3].as_str().unwrap_or("").to_string(),
            );
            if typ == "ROOT" || (typ == "IP_ADDRESS" && data == ip) {
                continue;
            }
            if !RECON_INTERESTING.contains(&typ.as_str()) {
                continue;
            }
            let m = if modu.is_empty() { "spiderfoot".to_string() } else { modu };
            push_finding(&mut seen, &mut out, &typ, &data, &m);
            if out.len() >= 60 {
                break;
            }
        }
    }
    let d = serde_json::json!({"state": "done", "scan": sid, "status": status, "done": true,
        "ts": now, "count": out.len(), "results": out});
    if let Ok(mut s) = st().lock() {
        s.recon.insert(key, d.clone());
    }
    d
}

fn recon_webhook(key: &str, ip: &str, hook: &str, token: &str, now: i64) -> serde_json::Value {
    if hook.is_empty() {
        return serde_json::json!({"state": "error", "error": "RECON_WEBHOOK_URL is empty"});
    }
    let body = serde_json::json!({"ip": ip}).to_string();
    let mut req = ureq::post(hook)
        .set("Content-Type", "application/json")
        .set("User-Agent", "ssh-sentinel-recon/1.0")
        .timeout(std::time::Duration::from_secs(25));
    if !token.is_empty() {
        req = req.set("Authorization", &format!("Bearer {}", token));
    }
    let payload: serde_json::Value = match req.send_string(&body) {
        Ok(r) => r.into_string().ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(serde_json::Value::Null),
        Err(e) => return serde_json::json!({"state": "error", "error": format!("webhook failed: {}", short_kind(&e.to_string()))}),
    };
    let items: Vec<serde_json::Value> = match &payload {
        serde_json::Value::Object(m) => m.get("findings").or_else(|| m.get("results")).and_then(|x| x.as_array()).cloned().unwrap_or_default(),
        serde_json::Value::Array(a) => a.clone(),
        _ => vec![],
    };
    let mut seen = std::collections::HashSet::new();
    let mut out = vec![];
    for f in items {
        if !f.is_object() {
            continue;
        }
        let typ = f.get("type").or_else(|| f.get("eventType")).and_then(|x| x.as_str()).unwrap_or("FINDING");
        let data = f.get("data").or_else(|| f.get("finding")).or_else(|| f.get("value")).or_else(|| f.get("info")).and_then(|x| x.as_str()).unwrap_or("").trim();
        let modu = f.get("module").or_else(|| f.get("source")).or_else(|| f.get("provider")).and_then(|x| x.as_str()).unwrap_or("webhook");
        if data.is_empty() || !seen.insert((typ.to_string(), data.to_string())) {
            continue;
        }
        out.push(serde_json::json!({"type": typ.chars().take(64).collect::<String>(),
            "data": data.chars().take(300).collect::<String>(),
            "module": modu.chars().take(64).collect::<String>()}));
        if out.len() >= 60 {
            break;
        }
    }
    let d = serde_json::json!({"state": "done", "scan": "webhook", "status": "FINISHED", "done": true,
        "ts": now, "count": out.len(), "results": out});
    if let Ok(mut s) = st().lock() {
        s.recon.insert(key.to_string(), d.clone());
    }
    d
}

fn trim(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn push_finding(
    seen: &mut std::collections::HashSet<(String, String)>,
    out: &mut Vec<serde_json::Value>,
    typ: &str,
    data: &str,
    modu: &str,
) {
    let data = data.trim();
    if data.is_empty() || !seen.insert((typ.to_string(), data.to_string())) {
        return;
    }
    out.push(serde_json::json!({"type": typ, "data": data.chars().take(300).collect::<String>(), "module": modu}));
}
