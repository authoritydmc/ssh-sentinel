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

echo "[1/3] Building image..."
docker build -t "$IMG" .
echo "[ OK ] Built $IMG"

echo "[2/4] Running with demo log (open mode)..."
docker run -d --name "$CONTAINER" -p "$HOST_PORT:8079" \
  -e HOST_ID=smoke -e AUTH_LOG=/srv/demo/auth.log.sample -e AUTH_MODE=none \
  -v "$PWD/demo/auth.log.sample:/srv/demo/auth.log.sample:ro" \
  "$IMG" >/dev/null
sleep 6
docker logs "$CONTAINER" 2>&1 | tail -n 5 || true

echo "[3/4] Health + API checks (incl. public abusers feed)..."
curl -s -f "http://localhost:$HOST_PORT/healthz" | grep -q ok
echo "[ OK ] /healthz -> ok"
SUMMARY=$(curl -s -f "http://localhost:$HOST_PORT/api/summary?host=all")
echo "$SUMMARY" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['ips'] >= 1, d; print('[ OK ] /api/summary ips=%d total=%d' % (d['ips'], d['total']))"
ABUSERS=$(curl -s -f "http://localhost:$HOST_PORT/api/abusers?per_page=50")
echo "$ABUSERS" | python3 -c "
import json,sys,ipaddress
d = json.load(sys.stdin)
assert d['total'] >= 1 and d['abusers'], d
blob = json.dumps(d['abusers'])
assert 'Accepted' not in blob, 'accepted logins leaked'
assert all(ipaddress.ip_address(a['ip']).is_global for a in d['abusers']), 'non-public IP leaked'
assert set(d['abusers'][0].keys()) <= {'ip','hits','first','last','users','attempted_users','cc','country','city','org','asn','lat','lon','flag'}, d['abusers'][0].keys()
print('[ OK ] /api/abusers total=%d safe-fields-only' % d['total'])
"

echo "[4/4] Local-auth gate (fail-closed default)..."
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
curl -s -f "http://localhost:$AHOST_PORT/healthz" | grep -q ok
echo "[ OK ] /healthz open in local mode"
if curl -s "http://localhost:$AHOST_PORT/api/summary?host=all" | grep -q '"total"'; then
  echo "[FAIL] /api/summary reachable without credentials"; exit 1
fi
echo "[ OK ] /api/summary -> 401 without credentials"
curl -s -f -u "smokeadmin:smoke-pass" "http://localhost:$AHOST_PORT/api/summary?host=all" | grep -q '"total"'
echo "[ OK ] /api/summary -> 200 with Basic credentials"
if curl -s -f -u "smokeadmin:wrong" "http://localhost:$AHOST_PORT/api/summary?host=all" >/dev/null 2>&1; then
  echo "[FAIL] wrong password accepted"; exit 1
fi
echo "[ OK ] wrong password -> 401"
curl -s -f "http://localhost:$AHOST_PORT/api/auth" | grep -q '"local"'
echo "[ OK ] /api/auth reports local mode"
docker rm -f "$ACONTAINER" >/dev/null 2>&1 || true

echo "Smoke test PASSED."
