#!/usr/bin/env python3
"""Generate a realistic demo auth.log (multi-country SSH attacks, 48h)."""
import random
from datetime import datetime, timedelta

random.seed(20261006)
OUT = "demo/auth.log.sample"
NOW = datetime.now().astimezone()

ATTACKERS = [
    ("IL", "77.91.71.90", ["admin", "root"], 140),
    ("CN", "175.6.158.150", ["admin", "user", "debian"], 246),
    ("NL", "94.154.43.56", ["user", "admin"], 120),
    ("GB", "2.57.121.25", ["admin", "oracle"], 60),
    ("SG", "103.143.11.150", ["root", "test"], 90),
    ("VN", "14.103.118.186", ["admin"], 45),
    ("IR", "5.160.120.40", ["admin", "ftpuser"], 55),
    ("BR", "177.12.44.9", ["user"], 30),
    ("US", "104.44.22.10", ["admin"], 25),
    ("DE", "159.69.33.21", ["root", "developer"], 35),
]
GOOD = [("ubuntu", "106.219.169.80", 6), ("deploy", "49.37.112.9", 4)]

lines = []
start = NOW - timedelta(hours=48)
for _cc, ip, users, n in ATTACKERS:
    for _ in range(n):
        ts = start + timedelta(seconds=random.randint(0, 48 * 3600))
        u = random.choice(users)
        r = random.random()
        if r < 0.45:
            lines.append((ts, "sshd[%d]: Failed password for %s %s from %s port %d ssh2" % (random.randint(1000, 99999), "invalid user " if random.random() < 0.4 else "", u, ip, random.randint(1024, 65000))))
        elif r < 0.75:
            lines.append((ts, "sshd[%d]: Invalid user %s from %s port %d" % (random.randint(1000, 99999), u, ip, random.randint(1024, 65000))))
        elif r < 0.9:
            lines.append((ts, "sshd[%d]: Disconnected from invalid user %s %s port %d [preauth]" % (random.randint(1000, 99999), u, ip, random.randint(1024, 65000))))
        else:
            lines.append((ts, "sshd[%d]: Connection closed by %s port %d [preauth]" % (random.randint(1000, 99999), ip, random.randint(1024, 65000))))
for u, ip, n in GOOD:
    for _ in range(n):
        ts = start + timedelta(seconds=random.randint(0, 48 * 3600))
        lines.append((ts, "sshd[%d]: Accepted publickey for %s from %s port %d ssh2" % (random.randint(1000, 99999), u, ip, random.randint(1024, 65000))))

lines.sort()
with open(OUT, "w") as f:
    for ts, msg in lines:
        f.write("%s %s\n" % (ts.isoformat(), msg))
print("wrote %d lines -> %s" % (len(lines), OUT))
