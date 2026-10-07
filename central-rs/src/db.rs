//! SQLite store. Tables: ip_stats, bans, reports, activity, kv.

use rusqlite::{Connection, OptionalExtension};
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Db {
    pub path: PathBuf,
    lock: Mutex<()>,
}

impl Db {
    pub fn new(data_dir: &str) -> Db {
        let p = PathBuf::from(data_dir);
        let _ = std::fs::create_dir_all(&p);
        let _ = std::fs::create_dir_all(p.join("hosts"));
        Db { path: p.join("sentinel.db"), lock: Mutex::new(()) }
    }

    pub fn hosts_dir(&self) -> PathBuf {
        self.path.parent().unwrap().join("hosts")
    }
    pub fn agents_file(&self) -> PathBuf {
        self.path.parent().unwrap().join("agents.json")
    }
    pub fn admin_file(&self) -> PathBuf {
        self.path.parent().unwrap().join("admin.json")
    }
    pub fn setup_token_file(&self) -> PathBuf {
        self.path.parent().unwrap().join("setup.token")
    }
    pub fn banlist_file(&self) -> PathBuf {
        self.path.parent().unwrap().join("banlist.txt")
    }

    pub fn open(&self) -> rusqlite::Result<Connection> {
        let c = Connection::open(&self.path)?;
        c.execute_batch("PRAGMA journal_mode=WAL")?;
        Ok(c)
    }

    pub fn init(&self) {
        let _g = self.lock.lock();
        if let Ok(c) = self.open() {
            let _ = c.execute_batch(
                "CREATE TABLE IF NOT EXISTS ip_stats
                 (ip TEXT PRIMARY KEY, hits INTEGER, users_json TEXT,
                  first REAL, last REAL, risk INTEGER, band TEXT,
                  reasons_json TEXT, updated REAL);
                 CREATE TABLE IF NOT EXISTS bans
                 (ip TEXT PRIMARY KEY, jail TEXT, reason TEXT, source TEXT,
                  created REAL, expires REAL, active INTEGER, fail2ban_ok INTEGER);
                 CREATE TABLE IF NOT EXISTS reports
                 (ip TEXT, provider TEXT, ts REAL, status TEXT, detail TEXT,
                  PRIMARY KEY (ip, provider));
                 CREATE TABLE IF NOT EXISTS activity
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT,
                  action TEXT, ip TEXT, detail TEXT);
                 CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT)",
            );
        }
    }

    pub fn activity_log(&self, actor: &str, action: &str, ip: &str, detail: &str) {
        let _g = self.lock.lock();
        if let Ok(c) = self.open() {
            let now = crate::clock_secs();
            let _ = c.execute(
                "INSERT INTO activity(ts, actor, action, ip, detail) VALUES(?,?,?,?,?)",
                rusqlite::params![now, trunc(actor, 80), trunc(action, 40), trunc(ip, 45), trunc(detail, 500)],
            );
            let _ = c.execute(
                "DELETE FROM activity WHERE id NOT IN (SELECT id FROM activity ORDER BY id DESC LIMIT 2000)",
                [],
            );
        }
    }

    pub fn activity_list(&self, limit: i64) -> Vec<serde_json::Value> {
        let lim = limit.clamp(1, 500);
        let mut out = vec![];
        if let Ok(c) = self.open() {
            if let Ok(mut st) = c.prepare(
                "SELECT ts, actor, action, ip, detail FROM activity ORDER BY id DESC LIMIT ?",
            ) {
                if let Ok(rows) = st.query_map([lim], |r| {
                    Ok((
                        r.get::<_, f64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                }) {
                    for r in rows.flatten() {
                        out.push(serde_json::json!({
                            "ts": (r.0 * 1000.0) as i64,
                            "actor": r.1, "action": r.2, "ip": r.3, "detail": r.4,
                        }));
                    }
                }
            }
        }
        out
    }

    pub fn kv_set(&self, key: &str, value: &str) {
        if let Ok(c) = self.open() {
            let _ = c.execute(
                "INSERT OR REPLACE INTO kv(key, value) VALUES(?,?)",
                rusqlite::params![key, value],
            );
        }
    }

    pub fn write_banlist(&self, ips: &[String]) {
        let mut v: Vec<&str> = ips.iter().map(|s| s.as_str()).collect();
        v.sort();
        v.dedup();
        let _ = std::fs::write(self.banlist_file(), v.join("\n") + if v.is_empty() { "" } else { "\n" });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(self.banlist_file(), std::fs::Permissions::from_mode(0o600));
        }
    }

    pub fn agents(&self) -> std::collections::HashMap<String, String> {
        std::fs::read_to_string(self.agents_file())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn read_admin(&self) -> serde_json::Value {
        std::fs::read_to_string(self.admin_file())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(serde_json::Value::Null)
    }

    pub fn write_admin(&self, user: &str, pass_hash: &str) -> bool {
        let body = serde_json::json!({"user": user, "pass_hash": pass_hash}).to_string();
        if std::fs::write(self.admin_file(), body).is_err() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(self.admin_file(), std::fs::Permissions::from_mode(0o600));
        }
        true
    }
}

fn trunc(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn ban_row_active(c: &Connection, ip: &str) -> Option<(String, f64, f64, i64)> {
    c.query_row(
        "SELECT source, created, expires, active FROM bans WHERE ip=?",
        [ip],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .optional()
    .ok()
    .flatten()
}
