# SSH Sentinel — multi-server SSH attack intel (SOC dashboard)

Central React dashboard + stdlib Python API + lightweight log-shipper agents.
Modelled on Beszel (hub/agent) and Dozzle (distributed logs): agents **push**
over the tailnet, central aggregates. Private repo.

```
agent (any server) --tailscale+bearer--> central (main server) --> UI
```

## Demo (any machine, 2 min)

```bash
docker compose --profile demo up --build
# open http://localhost:8081  (sample fleet log, 10 countries, 48h)
```

## Single server

```bash
cp .env.example .env   # set HOST_ID + SELF_PUBLIC_IPS
docker compose up -d --build
# open http://localhost:8079
```

## Fleet: central + join N servers (Tailscale recommended)

**On central (Server 1):** run the `central` service as above. Mint a join token:

```bash
docker exec ssh-sentinel python3 /srv/server.py gentoken oracle2
# -> host=oracle2, token=..., central=http://<this-host>:8079
```

**On the joining server (Server 2):** needs Tailscale up (`tailscale status`)
so it can reach central by tailnet name, then:

```bash
git clone <this-repo> && cd ssh-sentinel
CENTRAL_URL=http://<central-tailnet-name>:8079 AGENT_TOKEN=<token> sudo -E ./agent/install.sh
```

Verify on central: `curl localhost:8079/api/hosts`. The UI gains a host
filter (All hosts + per-host) once agents report.

Security notes: agents push outbound only (no inbound ports on members);
bearer per-host tokens in `data/agents.json` (0600); Tailscale gives
WireGuard identity + encryption; never expose 8079 publicly without SSO
in front. Rotate a host: `gentoken <host>` again + update its env + restart.

## Layout

| Path | What |
| :--- | :--- |
| `frontend/` | Vite + React 19 + Tailwind v4 SOC dashboard (code-split) |
| `backend/server.py` | stdlib API + static dist serving + agent push + host store |
| `agent/agent.py` | stdlib trailing shipper (systemd via `install.sh`) |
| `demo/` | sample log + generator for UI work without real attacks |
| `Dockerfile` | node build -> python:3.12 runtime |

API: `GET /api/summary?host=`, `/api/hosts`, `/api/tail?host=`,
`/api/ipinfo?host=`, `POST /api/recon`, `POST /api/agent/push` (bearer).
