#!/bin/sh
# One image, two roles. ROLE=central (default) serves the API + UI.
# ROLE=agent tails AUTH_LOG and pushes to CENTRAL_URL.
set -eu
ROLE="${ROLE:-central}"
case "$ROLE" in
  agent)
    echo "role: agent ${AGENT_ID:-$(hostname)} -> ${CENTRAL_URL:-http://central:8079}" >&2
    if [ -z "${AGENT_TOKEN:-}" ]; then
      echo "role=agent needs AGENT_TOKEN (mint: server.py gentoken <host>)" >&2
      exit 1
    fi
    exec python3 /srv/agent.py
    ;;
  central)
    echo "role: central (API + UI on :8079)" >&2
    exec python3 /srv/server.py
    ;;
  *)
    echo "unknown ROLE=$ROLE (want central|agent)" >&2
    exit 1
    ;;
esac
