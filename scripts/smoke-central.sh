#!/usr/bin/env bash
# Central smoke test for the Rust binary. Needs curl plus jq.
set -euo pipefail
cd "$(dirname "$0")/.."

RSBIN="${RSBIN:-target/debug/ssh-sentinel}"
[ -x "$RSBIN" ] || { echo "[FAIL] missing Rust binary: $RSBIN (cargo build first)"; exit 1; }

WORK=$(mktemp -d)
cleanup() {
  kill "$CENTRAL_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

start() {
  # $1 = extra env assignments, $2 = log file, $3 = data suffix.
  # Uses globals PORT and BASE (one fixed port per stage).
  AUTH_LOG="$LOG" DATA_DIR="$WORK/$3" HOST_ID=smoke PORT="$PORT" \
    env $1 "$RSBIN" >"$2" 2>&1 &
  CENTRAL_PID=$!
  for _ in $(seq 1 40); do
    curl -s --max-time 2 "$BASE/healthz" | grep -q ok && break
    sleep 0.5
  done
}

is_global() {
  # Mirror the safe-feed rule: no private, loopback, link-local, CGNAT.
  case "$1" in
    10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*|127.*|169.254.*|0.*|224.*|24[0-9].*|25*|\
    100.6[4-9].*|100.7*|100.8*|100.9*|100.1[0-2]*|fc*|fd*|fe80*|::*1|::) return 1 ;;
  esac
  return 0
}

LOG="$PWD/demo/auth.log.sample"

echo "[1/4] Reads..."
PORT=18092; BASE="http://127.0.0.1:$PORT"
start "AUTH_MODE=none" /tmp/smoke-central.log data
curl -s --max-time 20 -f "$BASE/healthz" | grep -q ok
TOTAL=$(curl -s --max-time 20 -f "$BASE/api/summary?host=all" | jq -r .total)
IPS=$(curl -s --max-time 20 -f "$BASE/api/summary?host=all" | jq -r .ips)
[ "$TOTAL" -gt 0 ] && [ "$IPS" -ge 1 ] || { echo "[FAIL] empty summary"; exit 1; }
echo "[ OK ] summary total=$TOTAL ips=$IPS"
curl -s --max-time 20 -f "$BASE/api/abusers?per_page=50" > "$WORK/abusers.json"
jq -e '.total >= 1 and (.abusers | length > 0)' "$WORK/abusers.json" >/dev/null
jq -e '[.abusers[] | tojson] | join("") | contains("Accepted") | not' "$WORK/abusers.json" >/dev/null
echo "[ OK ] abusers safe-fields-only"
for ip in $(jq -r '.abusers[].ip' "$WORK/abusers.json"); do
  is_global "$ip" || { echo "[FAIL] non-public IP listed: $ip"; exit 1; }
done
echo "[ OK ] all listed IPs public"
jq -e '(.abusers[0] | keys) - ["ip","hits","first","last","users","attempted_users","cc","country","city","org","asn","lat","lon","flag","risk","band","reasons"] | length == 0' "$WORK/abusers.json" >/dev/null
echo "[ OK ] abuser keys exact"
curl -s --max-time 20 -f "$BASE/api/tail?q=Failed&n=5" | grep -q Failed
echo "[ OK ] tail"
curl -s --max-time 20 -f "$BASE/api/admin/status" | grep -q setup_needed
echo "[ OK ] admin status"

echo "[2/4] Local gate..."
kill "$CENTRAL_PID" 2>/dev/null || true
sleep 1
PORT=18093; BASE="http://127.0.0.1:$PORT"
start "AUTH_MODE=local AUTH_USER=smokeadmin AUTH_PASSWORD=smoke-pass-123" /tmp/smoke-central2.log data2
if curl -s --max-time 20 "$BASE/api/summary?host=all" | grep -q '"total"'; then
  echo "[FAIL] summary open without login"; exit 1
fi
echo "[ OK ] 401 without creds"
curl -s --max-time 20 -f -u smokeadmin:smoke-pass-123 "$BASE/api/admin/config" | grep -q ban_enabled
echo "[ OK ] 200 with creds"
curl -s --max-time 20 -f -X POST "$BASE/api/admin/config" -u smokeadmin:smoke-pass-123 \
  -H 'Content-Type: application/json' -d '{"ban_threshold": 30}' | grep -q '"ban_threshold":30'
echo "[ OK ] config roundtrip"

echo "[3/4] Setup plus bans..."
kill "$CENTRAL_PID" 2>/dev/null || true
sleep 1
PORT=18094; BASE="http://127.0.0.1:$PORT"
start "AUTH_MODE=local ADMIN_SETUP_TOKEN=smoke-setup-token" /tmp/smoke-central3.log data3
curl -s --max-time 20 -f -X POST "$BASE/api/admin/setup" -H 'Content-Type: application/json' \
  -d '{"token":"smoke-setup-token","user":"smokeadmin","password":"smoke-pass-123"}' | grep -q '"ok": *true'
echo "[ OK ] setup"
IP=$(curl -s --max-time 20 -u smokeadmin:smoke-pass-123 "$BASE/api/abusers?per_page=5" | jq -r '.abusers[0].ip')
curl -s --max-time 20 -f -X POST "$BASE/api/admin/ban" -u smokeadmin:smoke-pass-123 \
  -H 'Content-Type: application/json' -d "{\"ip\":\"$IP\",\"reason\":\"smoke\"}" | grep -q '"ok": *true'
curl -s --max-time 20 -f -u smokeadmin:smoke-pass-123 "$BASE/api/banlist" | grep -q "$IP"
curl -s --max-time 20 -f -u smokeadmin:smoke-pass-123 "$BASE/api/admin/activity?limit=5" | grep -q ban
echo "[ OK ] ban plus banlist plus activity"
curl -s --max-time 20 -f -X POST "$BASE/api/admin/unban" -u smokeadmin:smoke-pass-123 \
  -H 'Content-Type: application/json' -d "{\"ip\":\"$IP\"}" | grep -q '"ok": *true'
echo "[ OK ] unban"

echo "[4/4] OIDC fail-closed..."
kill "$CENTRAL_PID" 2>/dev/null || true
sleep 1
PORT=18095; BASE="http://127.0.0.1:$PORT"
start "AUTH_MODE=oidc" /tmp/smoke-central4.log data4
curl -s --max-time 20 -f "$BASE/api/auth" | grep -q '"oidc"'
if curl -s --max-time 20 "$BASE/api/summary?host=all" | grep -q '"total"'; then
  echo "[FAIL] summary open without SSO session"; exit 1
fi
curl -s --max-time 20 "$BASE/oidc/login" | grep -q 'OIDC not configured'
echo "[ OK ] oidc fail-closed"
echo "Smoke test PASSED."
