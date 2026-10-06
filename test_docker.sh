#!/usr/bin/env bash
# SSH Sentinel - Docker smoke test (house style, cf. redirector test_docker.sh)
# Builds the image and verifies it end-to-end with the synthetic demo log.
set -euo pipefail
cd "$(dirname "$0")"

IMG="ssh-sentinel:test"
CONTAINER="ssh-sentinel-test-$$"

pick_port() {
  python3 - <<'PY' 2>/dev/null || true
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

HOST_PORT=$(pick_port)
[ -z "${HOST_PORT:-}" ] && HOST_PORT=18079
echo "Using host port: $HOST_PORT"

cleanup() {
  echo
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! docker info >/dev/null 2>&1; then
  echo "[FAIL] Docker daemon not running."
  exit 1
fi
echo "[ OK ] Docker daemon running."

echo "[1/7] Building image..."
docker build -t "$IMG" .
echo "[ OK ] Built $IMG"

echo "[2/7] Running with demo log (open mode)..."
docker run -d --name "$CONTAINER" -p "$HOST_PORT:8079" \
  -e HOST_ID=smoke -e AUTH_LOG=/srv/demo/auth.log.sample -e AUTH_MODE=none \
  -v "$PWD/demo/auth.log.sample:/srv/demo/auth.log.sample:ro" \
  "$IMG" >/dev/null
sleep 6
docker logs "$CONTAINER" 2>&1 | tail -n 5 || true

echo "[3/7] Health + API checks (incl. public abusers feed)..."
curl -s --max-time 20 -f "http://localhost:$HOST_PORT/healthz" | grep -q ok
echo "[ OK ] /healthz -> ok"
SUMMARY=$(curl -s --max-time 20 -f "http://localhost:$HOST_PORT/api/summary?host=all")
echo "$SUMMARY" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['ips'] >= 1, d; print('[ OK ] /api/summary ips=%d total=%d' % (d['ips'], d['total']))"
ABUSERS=$(curl -s --max-time 20 -f "http://localhost:$HOST_PORT/api/abusers?per_page=50")
echo "$ABUSERS" | python3 -c "
import json,sys,ipaddress
d = json.load(sys.stdin)
assert d['total'] >= 1 and d['abusers'], d
blob = json.dumps(d['abusers'])
assert 'Accepted' not in blob, 'accepted logins leaked'
assert all(ipaddress.ip_address(a['ip']).is_global for a in d['abusers']), 'non-public IP leaked'
assert set(d['abusers'][0].keys()) <= {'ip','hits','first','last','users','attempted_users','cc','country','city','org','asn','lat','lon','flag','risk','band','reasons'}, d['abusers'][0].keys()
print('[ OK ] /api/abusers total=%d safe-fields-only' % d['total'])
"

echo "[4/7] Local-auth gate (fail-closed default)..."
ACONTAINER="${CONTAINER}-auth"
AHOST_PORT=$(pick_port)
[ -z "${AHOST_PORT:-}" ] && AHOST_PORT=18080
HASH=$(docker run --rm "$IMG" python3 /srv/server.py genhash "smoke-pass" 2>/dev/null | grep -o 'pbkdf2-sha256\$[^ ]*')
[ -z "${HASH:-}" ] && { echo "[FAIL] genhash produced no hash"; exit 1; }
docker run -d --name "$ACONTAINER" -p "$AHOST_PORT:8079" \
  -e HOST_ID=smoke-auth -e AUTH_LOG=/srv/demo/auth.log.sample \
  -e AUTH_MODE=local -e AUTH_USER=smokeadmin -e AUTH_PASS_HASH="$HASH" \
  -v "$PWD/demo/auth.log.sample:/srv/demo/auth.log.sample:ro" \
  "$IMG" >/dev/null
sleep 6
curl -s --max-time 20 -f "http://localhost:$AHOST_PORT/healthz" | grep -q ok
echo "[ OK ] /healthz open in local mode"
if curl -s --max-time 20 "http://localhost:$AHOST_PORT/api/summary?host=all" | grep -q '"total"'; then
  echo "[FAIL] /api/summary reachable without credentials"; exit 1
fi
echo "[ OK ] /api/summary -> 401 without credentials"
curl -s --max-time 20 -f -u "smokeadmin:smoke-pass" "http://localhost:$AHOST_PORT/api/summary?host=all" | grep -q '"total"'
echo "[ OK ] /api/summary -> 200 with Basic credentials"
if curl -s --max-time 20 -f -u "smokeadmin:wrong" "http://localhost:$AHOST_PORT/api/summary?host=all" >/dev/null 2>&1; then
  echo "[FAIL] wrong password accepted"; exit 1
fi
echo "[ OK ] wrong password -> 401"
curl -s --max-time 20 -f "http://localhost:$AHOST_PORT/api/auth" | grep -q '"local"'
echo "[ OK ] /api/auth reports local mode"
docker rm -f "$ACONTAINER" >/dev/null 2>&1 || true

echo "[5/7] Public abusers (open feed + page, whitelist honored)..."
PCONTAINER="${CONTAINER}-pub"
PHOST_PORT=$(pick_port)
[ -z "${PHOST_PORT:-}" ] && PHOST_PORT=18082
docker run -d --name "$PCONTAINER" -p "$PHOST_PORT:8079" \
  -e HOST_ID=smoke-pub -e AUTH_LOG=/srv/demo/auth.log.sample \
  -e AUTH_MODE=local -e AUTH_USER=smokeadmin -e AUTH_PASS_HASH="$HASH" \
  -e ABUSERS_PUBLIC=1 -e WHITELIST_IPS=175.6.158.150 \
  -v "$PWD/demo/auth.log.sample:/srv/demo/auth.log.sample:ro" \
  "$IMG" >/dev/null
sleep 6
if curl -s --max-time 20 "http://localhost:$PHOST_PORT/api/summary?host=all" | grep -q '"total"'; then
  echo "[FAIL] summary open despite local mode"; exit 1
fi
echo "[ OK ] /api/summary still gated"
ABPUB=$(curl -s --max-time 20 -f "http://localhost:$PHOST_PORT/api/abusers?per_page=50")
echo "$ABPUB" | python3 -c "
import json,sys
d = json.load(sys.stdin)
assert d['total'] >= 1, d
assert not any(a['ip'] == '175.6.158.150' for a in d['abusers']), 'whitelisted IP listed'
assert all(a['hits'] >= 5 and a['risk'] >= 25 and a['band'] in ('low','medium','high','critical') for a in d['abusers']), 'quality bar'
print('[ OK ] /api/abusers open, whitelisted IP absent, scored')
"
curl -s --max-time 20 -f "http://localhost:$PHOST_PORT/abusers" | grep -q 'public abusers'
echo "[ OK ] /abusers leaderboard page open"
curl -s --max-time 20 -f "http://localhost:$PHOST_PORT/api/self" | grep -q '"ip"'
echo "[ OK ] /api/self open"
docker rm -f "$PCONTAINER" >/dev/null 2>&1 || true

echo "[6/7] Built-in OIDC gate (unconfigured IdP fails closed)..."
OCONTAINER="${CONTAINER}-oidc"
OHOST_PORT=$(pick_port)
[ -z "${OHOST_PORT:-}" ] && OHOST_PORT=18081
docker run -d --name "$OCONTAINER" -p "$OHOST_PORT:8079" \
  -e HOST_ID=smoke-oidc -e AUTH_LOG=/srv/demo/auth.log.sample \
  -e AUTH_MODE=oidc \
  -v "$PWD/demo/auth.log.sample:/srv/demo/auth.log.sample:ro" \
  "$IMG" >/dev/null
sleep 6
curl -s --max-time 20 -f "http://localhost:$OHOST_PORT/api/auth" | grep -q '"oidc"'
echo "[ OK ] /api/auth reports oidc mode"
if curl -s --max-time 20 "http://localhost:$OHOST_PORT/api/summary?host=all" | grep -q '"total"'; then
  echo "[FAIL] /api/summary reachable without SSO session"; exit 1
fi
echo "[ OK ] /api/summary -> 401 without session"
curl -s --max-time 20 "http://localhost:$OHOST_PORT/oidc/login" | grep -q 'OIDC not configured'
echo "[ OK ] /oidc/login reports missing OIDC_* (fail-closed)"
docker rm -f "$OCONTAINER" >/dev/null 2>&1 || true

echo "[7/7] Admin setup + bans (fail-closed, banlist, activity)..."
SCONTAINER="${CONTAINER}-adm"
SHOST_PORT=$(pick_port)
[ -z "${SHOST_PORT:-}" ] && SHOST_PORT=18083
docker run -d --name "$SCONTAINER" -p "$SHOST_PORT:8079" \
  -e HOST_ID=smoke-adm -e AUTH_LOG=/srv/demo/auth.log.sample \
  -e AUTH_MODE=local -e ADMIN_SETUP_TOKEN=smoke-setup-token \
  -v "$PWD/demo/auth.log.sample:/srv/demo/auth.log.sample:ro" \
  "$IMG" >/dev/null
sleep 6
if curl -s --max-time 20 "http://localhost:$SHOST_PORT/api/admin/bans" | grep -q '"bans"'; then
  echo "[FAIL] admin bans open without login"; exit 1
fi
echo "[ OK ] /api/admin/bans gated"
curl -s --max-time 20 -f -X POST "http://localhost:$SHOST_PORT/api/admin/setup" \
  -H 'Content-Type: application/json' \
  -d '{"token":"smoke-setup-token","user":"smokeadmin","password":"smoke-pass-123"}' | grep -q '"ok"'
echo "[ OK ] first setup creates admin"
IP=$(curl -s --max-time 20 -u smokeadmin:smoke-pass-123 "http://localhost:$SHOST_PORT/api/abusers?per_page=5" | python3 -c "import json,sys; print(json.load(sys.stdin)['abusers'][0]['ip'])")
curl -s --max-time 20 -f -X POST "http://localhost:$SHOST_PORT/api/admin/ban" \
  -u smokeadmin:smoke-pass-123 -H 'Content-Type: application/json' \
  -d "{\"ip\":\"$IP\",\"reason\":\"smoke\"}" | grep -q '"ok": *true'
echo "[ OK ] ban $IP"
curl -s --max-time 20 -f -u smokeadmin:smoke-pass-123 "http://localhost:$SHOST_PORT/api/banlist" | grep -q "$IP"
echo "[ OK ] banlist has IP"
curl -s --max-time 20 -f -u smokeadmin:smoke-pass-123 "http://localhost:$SHOST_PORT/api/admin/activity?limit=5" | grep -q 'ban'
echo "[ OK ] activity logs ban"
curl -s --max-time 20 -f -X POST "http://localhost:$SHOST_PORT/api/admin/unban" \
  -u smokeadmin:smoke-pass-123 -H 'Content-Type: application/json' \
  -d "{\"ip\":\"$IP\"}" | grep -q '"ok": *true'
echo "[ OK ] unban $IP"
docker rm -f "$SCONTAINER" >/dev/null 2>&1 || true

echo "Smoke test PASSED."
