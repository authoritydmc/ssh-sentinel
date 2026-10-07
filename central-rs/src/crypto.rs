//! Password hashes (pbkdf2-sha256), random tokens, RS256 verify.

use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn random_token_urlsafe(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn mint_pass_hash(pw: &str) -> String {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut dk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(pw.as_bytes(), &salt, 200_000, &mut dk);
    format!("pbkdf2-sha256$200000${}${}", hex::encode(salt), hex::encode(dk))
}

fn parse_hash(s: &str) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    let mut it = s.split('$');
    if it.next()? != "pbkdf2-sha256" {
        return None;
    }
    let iters: u32 = it.next()?.parse().ok()?;
    let salt = hex::decode(it.next()?).ok()?;
    let want = hex::decode(it.next()?).ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((iters, salt, want))
}

pub fn verify_pass_hash(hash: &str, pw: &str) -> bool {
    let (iters, salt, want) = match parse_hash(hash) {
        Some(v) => v,
        None => return false,
    };
    let mut got = vec![0u8; want.len()];
    pbkdf2::pbkdf2_hmac::<Sha256>(pw.as_bytes(), &salt, iters, &mut got);
    constant_eq(&got, &want)
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

pub fn b64url_dec(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

pub fn b64_std_enc(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 128 {
        vec![n as u8]
    } else {
        let mut b = vec![];
        let mut x = n;
        let mut tmp = vec![];
        while x > 0 {
            tmp.push((x & 0xff) as u8);
            x >>= 8;
        }
        b.push(0x80 | tmp.len() as u8);
        tmp.reverse();
        b.extend(tmp);
        b
    }
}

fn der_int(b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    while v.len() > 1 && v[0] == 0 {
        v.remove(0);
    }
    if v.first().map(|x| x & 0x80 != 0).unwrap_or(false) {
        v.insert(0, 0);
    }
    let mut out = vec![0x02];
    out.extend(der_len(v.len()));
    out.extend(v);
    out
}

/// PKCS#1 RSAPublicKey DER from raw (n, e). Used for JWKS RSA keys.
pub fn rsa_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut body = der_int(n);
    body.extend(der_int(e));
    let mut out = vec![0x30];
    out.extend(der_len(body.len()));
    out.extend(body);
    out
}

pub fn verify_rs256(msg: &[u8], sig: &[u8], der: &[u8]) -> bool {
    let key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        der,
    );
    key.verify(msg, sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_hash_roundtrip() {
        let h = mint_pass_hash("correct horse");
        assert!(verify_pass_hash(&h, "correct horse"));
        assert!(!verify_pass_hash(&h, "wrong"));
        assert!(!verify_pass_hash("junk", "x"));
        assert!(!verify_pass_hash("pbkdf2-sha256$abc$00$00", "x"));
    }

    #[test]
    fn der_shape() {
        // n=[0xc0] needs a zero pad (high bit set), e=[1,0,1] is plain.
        assert_eq!(
            rsa_der(&[0xc0], &[0x01, 0x00, 0x01]),
            vec![0x30, 0x09, 0x02, 0x02, 0x00, 0xc0, 0x02, 0x03, 0x01, 0x00, 0x01]
        );
    }

    #[test]
    fn rs256_rfc7515_vector() {
        // RFC 7515 Appendix A.2 test vector.
        let n_b64 = concat!(
            "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx",
            "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs",
            "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH",
            "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV",
            "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8",
            "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ");
        let msg = concat!(
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkz",
            "ODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ");
        let sig_b64 = concat!(
            "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7",
            "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4",
            "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K",
            "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv",
            "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB",
            "p0igcN_IoypGlUPQGe77Rw");
        let n = b64url_dec(n_b64).unwrap();
        let e = b64url_dec("AQAB").unwrap();
        let sig = b64url_dec(sig_b64).unwrap();
        assert_eq!(sig.len(), (n.len() * 8 + 7) / 8);
        let der = rsa_der(&n, &e);
        assert!(verify_rs256(msg.as_bytes(), &sig, &der));
        let mut bad = sig.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(!verify_rs256(msg.as_bytes(), &bad, &der));
        assert!(!verify_rs256(b"tampered", &sig, &der));
        assert!(!verify_rs256(msg.as_bytes(), &sig, b"junk-der"));
    }
}
