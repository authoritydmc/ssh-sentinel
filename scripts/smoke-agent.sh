#!/usr/bin/env bash
# Agent smoke test: the Rust agent pushes to the Rust central.
# Checks push stats, rotation resume, and state file shape.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="${AGENT_BIN:-target/release/ssh-sentinel-agent}"
[ -x "$BIN" ] || { echo "[FAIL] missing agent binary: $BIN (cargo build first)"; exit 1; }
CENTRAL_BIN="${CENTRAL_BIN:-target/debug/ssh-sentinel}"
[ -x "$CENTRAL_BIN" ] || { echo "[FAIL] missing central binary: $CENTRAL_BIN (cargo build first)"; exit 1; }

PORT="${SMOKE_PORT:-18091}"
BASE="http://127.0.0.1:$PORT"

WORK=$(mktemp -d)
CENTRAL_DATA="$WORK/data"
SAMPLE_LOG="$WORK/auth.log"
STATE="$WORK/state.json"
mkdir -p "$CENTRAL_DATA"
echo '{"smoke-host": "smoke-token-123"}' > "$CENTRAL_DATA/agents.json"

cat > "$SAMPLE_LOG" <<'EOF'
Oct  7 10:00:01 vps sshd[11]: Failed password for root from 77.91.71.90 port 5001 ssh2
Oct  7 10:00:02 vps sshd[11]: Failed password for root from 77.91.71.90 port 5002 ssh2
Oct  7 10:00:03 vps CRON[12]: (root) CMD (echo hello)
Oct  7 10:00:04 vps sudo: pam_unix(sudo:auth): authentication failure
EOF

export AUTH_LOG="$SAMPLE_LOG" DATA_DIR="$CENTRAL_DATA" HOST_ID=smoke AUTH_MODE=none PORT="$PORT"
"$CENTRAL_BIN" >/tmp/smoke-agent-central.log 2>&1 &
CENTRAL_PID=$!
cleanup() {
  kill "$CENTRAL_PID" 2>/dev/null || true
  [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

for i in $(seq 1 20); do
  curl -s --max-time 2 $BASE/healthz | grep -q ok && break
  sleep 0.5
done

CENTRAL_URL=$BASE AGENT_TOKEN=smoke-token-123 AGENT_ID=smoke-host \
  AUTH_LOG="$SAMPLE_LOG" PUSH_EVERY=1 AGENT_STATE="$STATE" "$BIN" >/tmp/smoke-agent.log 2>&1 &
AGENT_PID=$!
sleep 5

TOTAL=$(curl -s --max-time 10 "$BASE/api/summary?host=smoke-host" | jq -r .total)
[ "${TOTAL:-0}" -ge 2 ] || { echo "[FAIL] expected >=2 fails, got $TOTAL"; exit 1; }
echo "[ OK ] push: total=$TOTAL (2 sshd fails, CRON+sudo dropped)"

# Rotation: move the file away, write fresh lines, agent must ship them.
mv "$SAMPLE_LOG" "$SAMPLE_LOG.1"
cat > "$SAMPLE_LOG" <<'EOF'
Oct  7 10:05:01 vps sshd[21]: Failed password for admin from 77.91.71.90 port 5003 ssh2
Oct  7 10:05:02 vps sshd[21]: Failed password for admin from 77.91.71.90 port 5004 ssh2
Oct  7 10:05:03 vps sshd[21]: Failed password for admin from 77.91.71.90 port 5005 ssh2
EOF
sleep 4
TOTAL2=$(curl -s --max-time 10 "$BASE/api/summary?host=smoke-host" | jq -r .total)
[ "${TOTAL2:-0}" -ge 5 ] || { echo "[FAIL] rotation: expected >=5, got $TOTAL2"; exit 1; }
echo "[ OK ] rotation: total=$TOTAL2"
ONLINE=$(curl -s --max-time 10 "$BASE/api/hosts" | jq -r '.[] | select(.id=="smoke-host") | .online')
[ "$ONLINE" = "true" ] || { echo "[FAIL] pushing agent not online"; exit 1; }
echo "[ OK ] agent online in fleet"

jq -e '.ino and .offset' "$STATE" >/dev/null
echo "[ OK ] state file present"

BIN_SIZE=$(stat -c%s "$BIN" 2>/dev/null || stat -f%z "$BIN")
echo "[ OK ] binary size: $BIN_SIZE bytes"
echo "Agent smoke test PASSED."
