#!/usr/bin/env bash
# Central parity: Rust central must answer like Python central on the demo log.
# Boots both sides at once on two free ports, captures JSON, diffs fields.
# Network geo is skipped (racy). Timestamps are compared by shape only.
set -euo pipefail
cd "$(dirname "$0")/.."

RSBIN="${RSBIN:-central-rs/target/debug/ssh-sentinel}"
[ -x "$RSBIN" ] || { echo "[FAIL] missing Rust binary: $RSBIN (cargo build first)"; exit 1; }

free_port() {
  python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"
}
PYPORT=$(free_port)
RSPORT=$(free_port)

WORK=$(mktemp -d)
mkdir -p "$WORK/py" "$WORK/rs"
LOG="$PWD/demo/auth.log.sample"
cleanup() {
  kill "$PYPID" "$RSPID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "[1/4] Booting both sides (py=$PYPORT rs=$RSPORT)..."
AUTH_LOG="$LOG" DATA_DIR="$WORK/py" HOST_ID=smoke AUTH_MODE=none PORT="$PYPORT" \
  python3 backend/server.py >/tmp/parity-py.log 2>&1 &
PYPID=$!
AUTH_LOG="$LOG" DATA_DIR="$WORK/rs" HOST_ID=smoke AUTH_MODE=none PORT="$RSPORT" \
  "$RSBIN" >/tmp/parity-rs.log 2>&1 &
RSPID=$!
for _ in $(seq 1 40); do
  curl -s --max-time 2 "http://127.0.0.1:$PYPORT/healthz" | grep -q ok \
    && curl -s --max-time 2 "http://127.0.0.1:$RSPORT/healthz" | grep -q ok && break
  sleep 0.5
done

echo "[2/4] Capturing..."
PY="http://127.0.0.1:$PYPORT"
RS="http://127.0.0.1:$RSPORT"
for side in PY RS; do
  base="${!side}"
  tag=$(echo "$side" | tr 'A-Z' 'a-z')
  curl -s --max-time 20 "$base/api/summary?host=all" > "$WORK/$tag-summary.json"
  curl -s --max-time 20 "$base/api/abusers?per_page=100" > "$WORK/$tag-abusers.json"
  curl -s --max-time 20 "$base/api/admin/status" > "$WORK/$tag-status.json"
  curl -s --max-time 20 "$base/api/admin/config" > "$WORK/$tag-config.json"
  curl -s --max-time 20 "$base/api/hosts" > "$WORK/$tag-hosts.json"
  curl -s --max-time 20 "$base/api/self" > "$WORK/$tag-self.json"
  curl -s --max-time 20 "$base/api/tail?q=Failed&n=5" > "$WORK/$tag-tail.txt"
done
IP=$(python3 -c "import json; print(json.load(open('$WORK/py-abusers.json'))['abusers'][0]['ip'])")
for side in PY RS; do
  base="${!side}"
  tag=$(echo "$side" | tr 'A-Z' 'a-z')
  curl -s --max-time 20 -X POST "$base/api/admin/ban" \
    -H 'Content-Type: application/json' -d "{\"ip\":\"$IP\",\"reason\":\"parity\"}" > "$WORK/$tag-ban.json"
  curl -s --max-time 20 "$base/api/admin/bans" > "$WORK/$tag-bans.json"
  curl -s --max-time 20 "$base/api/banlist" > "$WORK/$tag-banlist.txt"
  curl -s --max-time 20 -X POST "$base/api/admin/unban" \
    -H 'Content-Type: application/json' -d "{\"ip\":\"$IP\"}" > /dev/null
  curl -s --max-time 20 "$base/api/ipinfo?ip=$IP" > "$WORK/$tag-ipinfo.json"
done

echo "[3/4] Gates (local mode)..."
kill "$PYPID" "$RSPID" 2>/dev/null || true
sleep 1
mkdir -p "$WORK/g-py" "$WORK/g-rs"
AUTH_LOG="$LOG" DATA_DIR="$WORK/g-py" HOST_ID=smoke AUTH_MODE=local AUTH_USER=admin AUTH_PASSWORD=paritypass123 PORT="$PYPORT" \
  python3 backend/server.py >/tmp/parity-gpy.log 2>&1 &
PYPID=$!
AUTH_LOG="$LOG" DATA_DIR="$WORK/g-rs" HOST_ID=smoke AUTH_MODE=local AUTH_USER=admin AUTH_PASSWORD=paritypass123 PORT="$RSPORT" \
  "$RSBIN" >/tmp/parity-grs.log 2>&1 &
RSPID=$!
for _ in $(seq 1 40); do
  curl -s --max-time 2 "http://127.0.0.1:$PYPORT/healthz" | grep -q ok \
    && curl -s --max-time 2 "http://127.0.0.1:$RSPORT/healthz" | grep -q ok && break
  sleep 0.5
done
curl -s --max-time 10 "http://127.0.0.1:$PYPORT/api/summary?host=all" > "$WORK/g-py.json"
curl -s --max-time 10 -u admin:paritypass123 "http://127.0.0.1:$PYPORT/api/admin/config" > "$WORK/g-py-auth.json"
curl -s --max-time 10 "http://127.0.0.1:$RSPORT/api/summary?host=all" > "$WORK/g-rs.json"
curl -s --max-time 10 -u admin:paritypass123 "http://127.0.0.1:$RSPORT/api/admin/config" > "$WORK/g-rs-auth.json"

echo "[4/4] Diff..."
WORK_DIR="$WORK" python3 - <<'PY'
import json, os, sys
W = os.environ["WORK_DIR"]
def load(n):
    with open(os.path.join(W, n)) as f:
        return json.load(f)
fails = []
def eq(name, a, b):
    if a != b:
        fails.append(name)
        print("DIFF %s:\n  py=%s\n  rs=%s" % (name, str(a)[:300], str(b)[:300]))
# summary core
ps, rs = load("py-summary.json"), load("rs-summary.json")
for k in ("total", "ips", "suspicious_count", "excluded_self", "privacy_mode"):
    eq("summary." + k, ps.get(k), rs.get(k))
eq("summary.timeline-fails", [t[1] for t in ps["timeline"]], [t[1] for t in rs["timeline"]])
eq("summary.logins-len", len(ps["logins"]), len(rs["logins"]))
pi = { (t["user"], t["ip"]): t["hits"] for t in ps["top"] }
ri = { (t["user"], t["ip"]): t["hits"] for t in rs["top"] }
eq("summary.top", pi, ri)
# abusers indexed by ip
pa = { a["ip"]: (a["hits"], a["risk"], a["band"]) for a in load("py-abusers.json")["abusers"] }
ra = { a["ip"]: (a["hits"], a["risk"], a["band"]) for a in load("rs-abusers.json")["abusers"] }
eq("abusers", pa, ra)
# status values (version can differ: dev vs file)
for k, v in load("py-status.json").items():
    if k in ("version",):
        continue
    eq("status." + k, v, load("rs-status.json").get(k))
eq("config.values", load("py-config.json")["values"], load("rs-config.json")["values"])
eq("config.locked", load("py-config.json")["locked"], load("rs-config.json")["locked"])
# hosts shape
ph = [(h["id"], h["local"], h["online"]) for h in load("py-hosts.json")]
rh = [(h["id"], h["local"], h["online"]) for h in load("rs-hosts.json")]
eq("hosts", ph, rh)
eq("self", load("py-self.json"), load("rs-self.json"))
# tail exact text
pt = open(os.path.join(W, "py-tail.txt")).read()
rt = open(os.path.join(W, "rs-tail.txt")).read()
eq("tail", pt, rt)
# bans flow
pb, rb = load("py-ban.json"), load("rs-ban.json")
eq("ban.ok", (pb.get("ok"), pb.get("ip"), pb.get("fail2ban_ok")), (rb.get("ok"), rb.get("ip"), rb.get("fail2ban_ok")))
pbs = sorted((b["ip"], b["jail"], b["reason"], b["source"], b["fail2ban_ok"]) for b in load("py-bans.json")["bans"])
rbs = sorted((b["ip"], b["jail"], b["reason"], b["source"], b["fail2ban_ok"]) for b in load("rs-bans.json")["bans"])
eq("bans", pbs, rbs)
eq("banlist", open(os.path.join(W, "py-banlist.txt")).read(), open(os.path.join(W, "rs-banlist.txt")).read())
# ipinfo history only (geo racy)
eq("ipinfo.history", load("py-ipinfo.json")["history"], load("rs-ipinfo.json")["history"])
# gates
eq("gate.local-401", load("g-py.json"), load("g-rs.json"))
eq("gate.local-config", load("g-py-auth.json")["values"], load("g-rs-auth.json")["values"])
if fails:
    print("PARITY FAILED: %d diffs" % len(fails))
    sys.exit(1)
print("Parity PASSED: all deterministic fields match.")
PY
echo "Parity test PASSED."
