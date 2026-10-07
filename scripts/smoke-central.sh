#!/usr/bin/env bash
# Central smoke test for the Rust binary (no Python needed for asserts
# except python3 JSON one-liners, which are CI helpers only, not runtime).
set -euo pipefail
cd "$(dirname "$0")/.."

RSBIN="${RSBIN:-central-rs/target/debug/ssh-sentinel}"
[ -x "$RSBIN" ] || { echo "[FAIL] missing Rust binary: $RSBIN (cargo build first)"; exit 1; }

free_port() {
  python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"
}
WORK=$(mktemp -d)
cleanup() {
  kill "$CENTRAL_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

LOG="$PWD/demo/auth.log.sample"
PORT=$(free_port)
BASE="http://127.0.0.1:$PORT"
AUTH_LOG="$LOG" DATA_DIR="$WORK/data" HOST_ID=smoke AUTH_MODE=none PORT="$PORT" \
  "$RSBIN" >/tmp/smoke-central.log 2>&1 &
CENTRAL_PID=$!
for _ in $(seq 1 40); do
  curl -s --max-time 2 "$BASE/healthz" | grep -q ok && break
  sleep 0.5
done

echo "[1/4] Reads..."
curl -s --max-time 20 -f "$BASE/healthz" | grep -q ok
curl -s --max-time 20 -f "$BASE/api/summary?host=all" > "$WORK/summary.json"
python3 -c "import json;d=json.load(open('$WORK/summary.json'));assert d['total']>0 and d['ips']>=1,(d['total'],d['ips']);print('[ OK ] summary total=%d ips=%d'%(d['total'],d['ips']))"
curl -s --max-time 20 -f "$BASE/api/abusers?per_page=50" > "$WORK/abusers.json"
python3 -c "
import json,sys,ipaddress
d = json.load(open('$WORK/abusers.json'))
assert d['total'] >= 1 and d['abusers'], d
blob = json.dumps(d['abusers'])
assert 'Accepted' not in blob, 'accepted logins leaked'
assert all(ipaddress.ip_address(a['ip']).is_global for a in d['abusers']), 'non-public IP leaked'
assert set(d['abusers'][0].keys()) <= {'ip','hits','first','last','users','attempted_users','cc','country','city','org','asn','lat','lon','flag','risk','band','reasons'}, d['abusers'][0].keys()
print('[ OK ] abusers total=%d safe-fields-only' % d['total'])
"
curl -s --max-time 20 -f "$BASE/api/tail?q=Failed&n=5" | grep -q Failed
echo "[ OK ] tail"
curl -s --max-time 20 -f "$BASE/api/admin/status" | grep -q setup_needed
echo "[ OK ] admin status"

echo "[2/4] Local gate..."
kill "$CENTRAL_PID" 2>/dev/null || true
sleep 1
PORT2=$(free_port)
BASE2="http://127.0.0.1:$PORT2"
AUTH_LOG="$LOG" DATA_DIR="$WORK/data2" HOST_ID=smoke AUTH_MODE=local AUTH_USER=smokeadmin AUTH_PASSWORD=smoke-pass-123 PORT="$PORT2" \
  "$RSBIN" >/tmp/smoke-central2.log 2>&1 &
CENTRAL_PID=$!
for _ in $(seq 1 40); do
  curl -s --max-time 2 "$BASE2/healthz" | grep -q ok && break
  sleep 0.5
done
if curl -s --max-time 20 "$BASE2/api/summary?host=all" | grep -q '"total"'; then
  echo "[FAIL] summary open without login"; exit 1
fi
echo "[ OK ] 401 without creds"
curl -s --max-time 20 -f -u smokeadmin:smoke-pass-123 "$BASE2/api/admin/config" | grep -q ban_enabled
echo "[ OK ] 200 with creds"
curl -s --max-time 20 -f -X POST "$BASE2/api/admin/config" -u smokeadmin:smoke-pass-123 \
  -H 'Content-Type: application/json' -d '{"ban_threshold": 30}' | grep -q '"ban_threshold":30'
echo "[ OK ] config roundtrip"

echo "[3/4] Setup plus bans..."
kill "$CENTRAL_PID" 2>/dev/null || true
sleep 1
PORT3=$(free_port)
BASE3="http://127.0.0.1:$PORT3"
AUTH_LOG="$LOG" DATA_DIR="$WORK/data3" HOST_ID=smoke AUTH_MODE=local ADMIN_SETUP_TOKEN=smoke-setup-token PORT="$PORT3" \
  "$RSBIN" >/tmp/smoke-central3.log 2>&1 &
CENTRAL_PID=$!
for _ in $(seq 1 40); do
  curl -s --max-time 2 "$BASE3/healthz" | grep -q ok && break
  sleep 0.5
done
curl -s --max-time 20 -f -X POST "$BASE3/api/admin/setup" -H 'Content-Type: application/json' \
  -d '{"token":"smoke-setup-token","user":"smokeadmin","password":"smoke-pass-123"}' | grep -q '"ok": *true'
echo "[ OK ] setup"
IP=$(curl -s --max-time 20 -u smokeadmin:smoke-pass-123 "$BASE3/api/abusers?per_page=5" | python3 -c "import json,sys; print(json.load(sys.stdin)['abusers'][0]['ip'])")
curl -s --max-time 20 -f -X POST "$BASE3/api/admin/ban" -u smokeadmin:smoke-pass-123 \
  -H 'Content-Type: application/json' -d "{\"ip\":\"$IP\",\"reason\":\"smoke\"}" | grep -q '"ok": *true'
curl -s --max-time 20 -f -u smokeadmin:smoke-pass-123 "$BASE3/api/banlist" | grep -q "$IP"
curl -s --max-time 20 -f -u smokeadmin:smoke-pass-123 "$BASE3/api/admin/activity?limit=5" | grep -q ban
echo "[ OK ] ban plus banlist plus activity"
curl -s --max-time 20 -f -X POST "$BASE3/api/admin/unban" -u smokeadmin:smoke-pass-123 \
  -H 'Content-Type: application/json' -d "{\"ip\":\"$IP\"}" | grep -q '"ok": *true'
echo "[ OK ] unban"

echo "[4/4] OIDC fail-closed..."
kill "$CENTRAL_PID" 2>/dev/null || true
sleep 1
PORT4=$(free_port)
BASE4="http://127.0.0.1:$PORT4"
AUTH_LOG="$LOG" DATA_DIR="$WORK/data4" HOST_ID=smoke AUTH_MODE=oidc PORT="$PORT4" \
  "$RSBIN" >/tmp/smoke-central4.log 2>&1 &
CENTRAL_PID=$!
for _ in $(seq 1 40); do
  curl -s --max-time 2 "$BASE4/healthz" | grep -q ok && break
  sleep 0.5
done
curl -s --max-time 20 -f "$BASE4/api/auth" | grep -q '"oidc"'
if curl -s --max-time 20 "$BASE4/api/summary?host=all" | grep -q '"total"'; then
  echo "[FAIL] summary open without SSO session"; exit 1
fi
curl -s --max-time 20 "$BASE4/oidc/login" | grep -q 'OIDC not configured'
echo "[ OK ] oidc fail-closed"
echo "Smoke test PASSED."
