#!/usr/bin/env bash
# Footprint report: image size plus runtime RSS and CPU for the central image.
# Runs in CI (footprint job) and locally with Docker. Prints a markdown table.
set -euo pipefail
cd "$(dirname "$0")/.."

IMG="ssh-sentinel:footprint"
CONTAINER="ssh-sentinel-footprint-$$"

HOST_PORT="${FOOTPRINT_PORT:-18090}"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/3] Building image..."
docker build -t "$IMG" .
SIZE=$(docker images "$IMG" --format "{{.Size}}")
echo "image size: $SIZE"

echo "[2/3] Booting with demo log..."
docker run -d --name "$CONTAINER" -p "$HOST_PORT:8079" \
  -e HOST_ID=footprint -e AUTH_LOG=/srv/demo/auth.log.sample -e AUTH_MODE=none \
  -v "$PWD/demo/auth.log.sample:/srv/demo/auth.log.sample:ro" \
  "$IMG" >/dev/null
sleep 8
curl -s --max-time 20 -f "http://localhost:$HOST_PORT/healthz" | grep -q ok
curl -s --max-time 20 -f "http://localhost:$HOST_PORT/api/summary?host=all" | grep -q '"total"'

echo "[3/3] Reading stats..."
STATS=$(docker stats --no-stream --format "{{.MemUsage}}|{{.MemPerc}}|{{.CPUPerc}}" "$CONTAINER")
MEM=$(echo "$STATS" | cut -d'|' -f1)
MEMPCT=$(echo "$STATS" | cut -d'|' -f2)
CPU=$(echo "$STATS" | cut -d'|' -f3)

TABLE="| metric | value |
| ------ | ----- |
| image size | $SIZE |
| RSS | $MEM ($MEMPCT) |
| CPU | $CPU |"
echo "$TABLE"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Footprint (central)"
    echo ""
    echo "$TABLE"
  } >> "$GITHUB_STEP_SUMMARY"
fi
echo "Footprint report DONE."
