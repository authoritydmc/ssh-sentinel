#!/usr/bin/env python3
"""Self-test the stdlib RS256 verifier against RFC 7515 Appendix A.2.

Run: python3 scripts/selftest_oidc.py (exit 0 = pass).
CI runs this in the backend job. No network, no deps.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend import server

# RFC 7515 A.2 RSA public key (whitespace stripped).
RFC_N = ("ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
         "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
         "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
         "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
         "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
         "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ")
RFC_E = "AQAB"
RFC_MSG = ("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkz"
           "ODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
RFC_SIG = ("cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
           "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
           "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
           "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
           "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
           "p0igcN_IoypGlUPQGe77Rw")


def main():
    n = int.from_bytes(server._b64url_dec(RFC_N), "big")
    e = int.from_bytes(server._b64url_dec(RFC_E), "big")
    msg = RFC_MSG.encode()
    sig = server._b64url_dec(RFC_SIG)
    assert len(sig) == (n.bit_length() + 7) // 8, "vector key/sig size mismatch"

    assert server._verify_rs256(msg, sig, n, e) is True, "valid vector must verify"

    bad = bytearray(sig)
    bad[-1] ^= 1
    assert server._verify_rs256(msg, bytes(bad), n, e) is False, "tampered sig must fail"

    assert server._verify_rs256(msg + b"x", sig, n, e) is False, "tampered msg must fail"

    assert server._verify_rs256(msg, sig[:-8], n, e) is False, "short sig must fail"

    # Cookie + session helpers round-trip.
    assert server._cookies("a=1; ssh_session=tok")["ssh_session"] == "tok"
    assert "HttpOnly" in server._cookie_str("ssh_session", "tok", max_age=60)

    print("selftest_oidc: 6/6 pass (RFC 7515 A.2 RS256 + helpers)")


if __name__ == "__main__":
    main()
