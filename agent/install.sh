#!/usr/bin/env bash
# Join a server to the SSH Sentinel fleet (run ON THE JOINING SERVER as root).
# Usage: CENTRAL_URL=http://oracle1:8079 AGENT_TOKEN=<from central gentoken> sudo -E ./install.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
: "${CENTRAL_URL:?set CENTRAL_URL, e.g. http://oracle1:8079 (tailscale name)}"
: "${AGENT_TOKEN:?set AGENT_TOKEN from central: python3 backend/server.py gentoken <host-id>}"
AGENT_ID="${AGENT_ID:-$(hostname -s)}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

install -m 0755 "$SRC_DIR/agent.py" /usr/local/bin/ssh-sentinel-agent
mkdir -p /var/lib/ssh-sentinel-agent /etc/ssh-sentinel-agent
cat > /etc/ssh-sentinel-agent/env <<EOF
CENTRAL_URL=$CENTRAL_URL
AGENT_TOKEN=$AGENT_TOKEN
AGENT_ID=$AGENT_ID
PUSH_EVERY=10
EOF
chmod 0600 /etc/ssh-sentinel-agent/env
cat > /etc/systemd/system/ssh-sentinel-agent.service <<'EOF'
[Unit]
Description=SSH Sentinel log shipper
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
EnvironmentFile=/etc/ssh-sentinel-agent/env
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-sentinel-agent
Restart=always
RestartSec=10
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ssh-sentinel-agent
sleep 3
systemctl is-active ssh-sentinel-agent
echo "joined as $AGENT_ID — check central /api/hosts"
