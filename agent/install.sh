#!/usr/bin/env bash
# Join a server to the SSH Sentinel fleet (run ON THE JOINING SERVER as root).
# Usage: CENTRAL_URL=http://central:8079 AGENT_TOKEN=<from central gentoken> sudo -E ./install.sh
# Fetches the static Rust agent binary from GitHub Releases. No build tools needed.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
: "${CENTRAL_URL:?set CENTRAL_URL, e.g. http://central-tailscale-name:8079 (tailscale name)}"
: "${AGENT_TOKEN:?set AGENT_TOKEN from central: ssh-sentinel gentoken <host-id>}"
AGENT_ID="${AGENT_ID:-$(hostname -s)}"
REPO="${REPO:-authoritydmc/ssh-sentinel}"
VERSION="${AGENT_VERSION:-$(cat "$(dirname "$0")/../VERSION" 2>/dev/null || echo 0.6.0)}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) TARGET="x86_64-unknown-linux-musl" ;;
  aarch64) TARGET="aarch64-unknown-linux-musl" ;;
  *) echo "unsupported arch: $ARCH (want x86_64 or aarch64)"; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
URL="https://github.com/${REPO}/releases/download/v${VERSION}/ssh-sentinel-agent-${TARGET}"
echo "fetching $URL"
curl -fsSL "$URL" -o "$TMP/ssh-sentinel-agent"
chmod 0755 "$TMP/ssh-sentinel-agent"
"$TMP/ssh-sentinel-agent" --help >/dev/null 2>&1 || true
install -m 0755 "$TMP/ssh-sentinel-agent" /usr/local/bin/ssh-sentinel-agent
mkdir -p /var/lib/ssh-sentinel-agent /etc/ssh-sentinel-agent
cat > /etc/ssh-sentinel-agent/env <<EOF
CENTRAL_URL=$CENTRAL_URL
AGENT_TOKEN=$AGENT_TOKEN
AGENT_ID=$AGENT_ID
PUSH_EVERY=10
SHIP_FILTER=${SHIP_FILTER:-sshd-only}
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
ExecStart=/usr/local/bin/ssh-sentinel-agent
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
