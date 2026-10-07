#!/usr/bin/env bash
# Rust agent parity test: the Rust binary must behave like agent/agent.py.
# Boots the real Python central, pushes via the Rust agent, checks stats.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="${AGENT_BIN:-agent-rs/target/release/ssh-sentinel-agent}"
[ -x "$BIN" ] || { echo "[FAIL] missing agent binary: $BIN"; exit 1; }

WORK=$(mktemp -d)
CENTRAL_DATA="$WORK/data"
SAMPLE_LOG="$WORK/auth.log"
STATE="$WORK/state.json"
mkdir -p "$CENTRAL_DATA"
echo '{"parity-host": "parity-token-123"}' > "$CENTRAL_DATA/agents.json"

cat > "$SAMPLE_LOG" <<'EOF'
Oct  7 10:00:01 vps sshd[11]: Failed password for root from 77.91.71.90 port 5001 ssh2
Oct  7 10:00:02 vps sshd[11]: Failed password for root from 77.91.71.90 port 5002 ssh2
Oct  7 10:00:03 vps CRON[12]: (root) CMD (echo hello)
Oct  7 10:00:04 vps sudo: pam_unix(sudo:auth): authentication failure
EOF

export AUTH_LOG="$SAMPLE_LOG" DATA_DIR="$CENTRAL_DATA" HOST_ID=smoke AUTH_MODE=none
python3 backend/server.py >/tmp/parity-central.log 2>&1 &
CENTRAL_PID=$!
cleanup() {
  kill "$CENTRAL_PID" 2>/dev/null || true
  [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

for i in $(seq 1 20); do
  curl -s --max-time 2 http://127.0.0.1:8079/healthz | grep -q ok && break
  sleep 0.5
done

CENTRAL_URL=http://127.0.0.1:8079 AGENT_TOKEN=parity-token-123 AGENT_ID=parity-host \
  AUTH_LOG="$SAMPLE_LOG" PUSH_EVERY=1 AGENT_STATE="$STATE" "$BIN" >/tmp/parity-agent.log 2>&1 &
AGENT_PID=$!
sleep 5

TOTAL=$(curl -s --max-time 10 "http://127.0.0.1:8079/api/summary?host=parity-host" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['total'])")
[ "${TOTAL:-0}" -ge 2 ] || { echo "[FAIL] expected >=2 fails, got $TOTAL"; exit 1; }
echo "[ OK ] push parity: total=$TOTAL (2 sshd fails, CRON+sudo dropped)"

# Rotation: move the file away, write fresh lines, agent must ship them.
mv "$SAMPLE_LOG" "$SAMPLE_LOG.1"
cat > "$SAMPLE_LOG" <<'EOF'
Oct  7 10:05:01 vps sshd[21]: Failed password for admin from 77.91.71.90 port 5003 ssh2
Oct  7 10:05:02 vps sshd[21]: Failed password for admin from 77.91.71.90 port 5004 ssh2
Oct  7 10:05:03 vps sshd[21]: Failed password for admin from 77.91.71.90 port 5005 ssh2
EOF
sleep 4
TOTAL2=$(curl -s --max-time 10 "http://127.0.0.1:8079/api/summary?host=parity-host" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['total'])")
[ "${TOTAL2:-0}" -ge 5 ] || { echo "[FAIL] rotation: expected >=5, got $TOTAL2"; exit 1; }
echo "[ OK ] rotation parity: total=$TOTAL2"

python3 -c "import json; d=json.load(open('$STATE')); assert 'ino' in d and 'offset' in d, d; print('[ OK ] state file:', d)"

BIN_SIZE=$(stat -c%s "$BIN" 2>/dev/null || stat -f%z "$BIN")
echo "[ OK ] binary size: $BIN_SIZE bytes"
echo "Parity test PASSED."
