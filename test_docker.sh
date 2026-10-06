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

echo "[2/3] Running with demo log..."
docker run -d --name "$CONTAINER" -p "$HOST_PORT:8079" \
  -e HOST_ID=smoke -e AUTH_LOG=/srv/demo/auth.log.sample \
  -v "$PWD/demo/auth.log.sample:/srv/demo/auth.log.sample:ro" \
  "$IMG" >/dev/null
sleep 6
docker logs "$CONTAINER" 2>&1 | tail -n 5 || true

echo "[3/3] Health + API checks..."
curl -s -f "http://localhost:$HOST_PORT/healthz" | grep -q ok
echo "[ OK ] /healthz -> ok"
SUMMARY=$(curl -s -f "http://localhost:$HOST_PORT/api/summary?host=all")
echo "$SUMMARY" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['ips'] >= 1, d; print('[ OK ] /api/summary ips=%d total=%d' % (d['ips'], d['total']))"

echo "Smoke test PASSED."
