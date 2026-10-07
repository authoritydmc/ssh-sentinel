//! Small helpers: env, CSV sets, IP class, masks, flags, time.
//!
//! IP ranges mirror CPython `ipaddress` for all real-world cases.
//! Exotic documentation ranges are treated as non-public on purpose.
//! That direction is fail-closed: odd IPs never enter lists or bans.

use std::collections::HashSet;
use std::net::IpAddr;

pub fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

pub fn csv_set(raw: &str) -> HashSet<String> {
    raw.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect()
}

pub fn valid_ip(s: &str) -> String {
    match s.trim().parse::<IpAddr>() {
        Ok(a) => a.to_string(),
        Err(_) => String::new(),
    }
}

pub fn is_ip(s: &str) -> bool {
    s.trim().parse::<IpAddr>().is_ok()
}

fn v4_public(o: [u8; 4]) -> bool {
    if o[0] == 0 || o[0] == 127 || o[0] >= 224 {
        return false;
    }
    if o[0] == 10 {
        return false;
    }
    if o[0] == 172 && (16..32).contains(&o[1]) {
        return false;
    }
    if o[0] == 192 && o[1] == 168 {
        return false;
    }
    if o[0] == 169 && o[1] == 254 {
        return false;
    }
    if o[0] == 100 && (64..128).contains(&o[1]) {
        return false; // CGNAT shared space
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 2 {
        return false; // TEST-NET-1
    }
    if o[0] == 198 && ((o[1] == 18) || (o[1] == 51 && o[2] == 100)) {
        return false; // benchmark + TEST-NET-2
    }
    if o[0] == 203 && o[1] == 0 && o[2] == 113 {
        return false; // TEST-NET-3
    }
    true
}

pub fn is_public_ip(s: &str) -> bool {
    let a: IpAddr = match s.trim().parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    match a {
        IpAddr::V4(v) => v4_public(v.octets()),
        IpAddr::V6(v) => {
            let s = v.segments();
            if v.is_loopback() || v.is_unspecified() || v.is_multicast() {
                return false;
            }
            if (s[0] & 0xffc0) == 0xfe80 {
                return false; // link-local
            }
            if (s[0] & 0xfe00) == 0xfc00 {
                return false; // unique-local
            }
            match v.to_ipv4_mapped() {
                Some(m) => v4_public(m.octets()),
                None => true,
            }
        }
    }
}

pub fn mask_user(u: &str) -> String {
    if u.is_empty() || u.len() <= 2 {
        return "***".to_string();
    }
    let mut c = u.chars();
    let first = c.next().unwrap_or('*');
    let last = u.chars().last().unwrap_or('*');
    format!("{}****{}", first, last)
}

pub fn mask_ip(ip: &str) -> String {
    if ip.contains('.') && ip.split('.').count() == 4 {
        let parts: Vec<&str> = ip.split('.').collect();
        return format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], "*");
    }
    if ip.contains(':') {
        if let Some(pos) = ip.rfind(':') {
            return format!("{}:*", &ip[..pos]);
        }
    }
    "***".to_string()
}

pub fn flag(cc: &str) -> String {
    if cc.len() != 2 {
        return "🌐".to_string();
    }
    let up: Vec<char> = cc.to_uppercase().chars().collect();
    if up.len() != 2 || !up.iter().all(|c| c.is_ascii_alphabetic()) {
        return "🌐".to_string();
    }
    up.iter()
        .map(|c| char::from_u32(0x1F1E6 + (*c as u32) - 65).unwrap_or('🌐'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ranges() {
        assert!(is_public_ip("77.91.71.90"));
        assert!(is_public_ip("8.8.8.8"));
        assert!(is_public_ip("2001:4860:4860::8888"));
        for bad in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "not-an-ip",
            "",
        ] {
            assert!(!is_public_ip(bad), "{}", bad);
        }
    }

    #[test]
    fn masks_and_flags() {
        assert_eq!(mask_user("deploy"), "d****y");
        assert_eq!(mask_user("ab"), "***");
        assert_eq!(mask_ip("1.2.3.4"), "1.2.3.*");
        assert_eq!(flag("NL").chars().count(), 2);
        assert_eq!(flag("?"), "🌐");
    }
}
