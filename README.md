# 🛡️ SSH Sentinel — multi-server SSH attack intel (SOC dashboard)

Central React dashboard + stdlib-only Python API + lightweight log-shipper agents.
Modelled on **Beszel** (hub/agent) and **Dozzle** (distributed logs): agents **push**
over your tailnet, central aggregates. No database, no dependencies at runtime.

![Docker](https://img.shields.io/badge/docker-rajlabs%2Fssh--sentinel-blue?logo=docker)
![GHCR](https://img.shields.io/badge/ghcr-ssh--sentinel-blue?logo=github)
![License](https://img.shields.io/badge/license-MIT-green)
![Stack](https://img.shields.io/badge/frontend-React19%20%2B%20Tailwind4-58a6ff)
![Backend](https://img.shields.io/badge/backend-python%20stdlib-3fb950)

```
agent (any server) --tailscale+bearer--> central (main server) --> UI
```

## 🤖 AI install (fastest path)

```bash
curl -fsSL https://raw.githubusercontent.com/authoritydmc/ssh-sentinel/master/scripts/ai-install.sh | bash
```

Then paste the prompt from [`AI.md`](AI.md) into your AI. The AI clones,
configures, deploys, and verifies. It obeys [`AGENTS.md`](AGENTS.md).

## ✨ Features

| Area | What you get |
| ---- | ------------ |
| **Overview** | Failed attempts, attacker IPs, successful logins, peak hour, top origin, most-wanted user |
| **Trends** | 48h failed-vs-accepted timeline, auth-outcome donut |
| **Map** | World attack map (lat/lon pins) + top attacking regions |
| **Attackers** | Top 25 user@IP pairs, flag, city/org/ASN, recon badge, click for full intel |
| **Intel modal** | Geo, org/ISP, ASN, rDNS, RDAP net, first/last seen, users tried, 48h activity bars, full log chain, optional SpiderFoot recon (cached 7d) |
| **Live events** | Tailable `/var/log/auth.log` (or fleet-merged), filter, pause, newest/oldest first, 15s refresh |
| **Fleet** | N agents push over HTTPS+bearer; host filter (All + per-host), online dot (120s), per-host timelines |
| **Self-noise filter** | Container/node egress + `SELF_PUBLIC_IPS` excluded from attacker stats (count shown separately) |
| **Ops** | Single static image, healthcheck on `/healthz`, no DB, JSON files only |

## 🎯 Use cases

1. **Single VPS watchtower** — see who is hammering your SSH right now, which users they want, which countries they come from.
2. **Fleet SOC** — 5–50 servers behind Tailscale, one dashboard. Agents push outbound only; members open zero inbound ports.
3. **Post-incident review** — click an IP → full log chain + RDAP/rDNS + recon findings, export the story.
4. **Demo / UI work** — synthetic 48h, 10-country log (`--profile demo`) without touching real auth logs.
5. **Homelab gateway** — runs next to Traefik/Authentik; keep 8079 on tailnet, put SSO in front for remote access.

## 🏗️ Architecture

Full design (diagrams + procedures, simplified English): [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
┌────────────┐  tail + push (10s)   ┌─────────────────────┐
│  member-01 │ ── Bearer:TOKEN ───▶ │      central        │
│ /var/log/  │  outbound only       │  server.py (stdlib) │
│ auth.log   │                      │  + React dist       │
└────────────┘                      │  data/hosts/*.jsonl │
┌────────────┐                      │  data/agents.json   │
│  member-02 │ ───────────────────▶ │  :8079  /healthz    │
└────────────┘                      └─────────┬───────────┘
                                              │ :8079 (tailnet only)
                                              ▼
                                    React 19 SOC dashboard
```

- **Backend** (`backend/server.py`): stdlib `ThreadingHTTPServer`, serves `dist/` + JSON API, parses syslog + ISO timestamps, enriches via ip-api/RDAP/rDNS (cached), optional SpiderFoot recon.
- **Agent** (`agent/agent.py`): stdlib tailer, inode+offset resume across rotation/restarts, exponential backoff, `PUSH_EVERY=10` default.
- **Frontend** (`frontend/`): Vite + React 19 + Tailwind v4, code-split charts/map/modal, 60s auto-refresh, base path `/ssh/`.

## 🚀 Quickstart

### Option A — prebuilt image (recommended)

```bash
# Docker Hub
docker run -d --name ssh-sentinel --restart unless-stopped \
  -p 8079:8079 \
  -e HOST_ID=central \
  -v sentinel_data:/srv/data \
  -v /var/log/auth.log:/var/log/auth.log:ro \
  rajlabs/ssh-sentinel:latest

# or GHCR
docker run -d --name ssh-sentinel --restart unless-stopped \
  -p 8079:8079 \
  -e HOST_ID=central \
  -v sentinel_data:/srv/data \
  -v /var/log/auth.log:/var/log/auth.log:ro \
  ghcr.io/authoritydmc/ssh-sentinel:latest

# open http://localhost:8079  (or http://<tailnet-name>:8079 in fleet)
curl -s localhost:8079/healthz  # -> ok
```

### Option B — compose (single server)

```bash
git clone https://github.com/authoritydmc/ssh-sentinel.git && cd ssh-sentinel
cp .env.example .env   # set HOST_ID + SELF_PUBLIC_IPS + AUTH_* login
docker compose up -d --build
# open http://localhost:8079 (image default AUTH_MODE=local is fail-closed:
# set AUTH_USER + AUTH_PASS_HASH in .env, or AUTH_MODE=none on a private net)
```

Mint a local-login hash (never commit the password or hash):

```bash
docker exec -it ssh-sentinel python3 /srv/server.py genhash
# -> AUTH_PASS_HASH=pbkdf2-sha256$200000$...   (paste into .env, compose up -d)
```

Behind Authentik + Traefik instead (same ForwardAuth pattern as Dozzle):

```yaml
# central labels (illustrative) — Authentik decides who gets in,
# central trusts the passed identity in AUTH_MODE=forward/oidc
labels:
  - "traefik.http.routers.ssh.middlewares=authentik@docker"
  - "traefik.http.middlewares.authentik.forwardauth.address=http://authentik:9000/outpost.goauthentik.io/auth/traefik"
  - "traefik.http.middlewares.authentik.forwardauth.trustForwardHeader=true"
  - "traefik.http.middlewares.authentik.forwardauth.authResponseHeaders=X-Forwarded-User,X-Forwarded-Email"
```

```bash
# central env for that setup
AUTH_MODE=forward
AUTH_ALLOWED_USERS=alice,bob@example.com   # optional allowlist
# headers are only honored from AUTH_TRUSTED_PROXIES (spoof-safe by default)
```

### Built-in SSO: no proxy needed (`AUTH_MODE=oidc`)

Central speaks OIDC itself (authorization-code flow, RS256, server sessions).
In Authentik, create a Provider (type OAuth2/OpenID, confidential client)
plus an Application, and set:

- Redirect URIs: `https://<your-host>/oidc/callback`
- Signing key: any RSA key (RS256 is required)
- Scopes: `openid email profile`

```bash
# central env
AUTH_MODE=oidc
OIDC_ISSUER=https://auth.example.com/application/o/ssh-sentinel/
OIDC_CLIENT_ID=<from authentik>
OIDC_CLIENT_SECRET=<from authentik>
OIDC_REDIRECT_URL=https://<your-host>/oidc/callback
AUTH_ALLOWED_USERS=alice@example.com   # optional allowlist
```

Open the UI → it redirects to Authentik → back with a session cookie
(HttpOnly, 12h default via `OIDC_SESSION_TTL`). `/oidc/logout` ends it.
`OIDC_COOKIE_SECURE=1` when central serves HTTPS directly.

Or copy-paste ready: [`examples/sso-traefik-authentik.yml`](examples/sso-traefik-authentik.yml)

```bash
SSO_HOST=ssh.example.com AUTH_ALLOWED_USERS=alice@example.com \
  docker compose -f docker-compose.yml -f examples/sso-traefik-authentik.yml up -d --build
```

Other SSO front doors that work with `AUTH_MODE=forward` (no code changes):

| Provider | How |
| -------- | --- |
| Authelia + Traefik/Nginx | ForwardAuth `authResponseHeaders: Remote-User, Remote-Email` — trusted `Remote-User` header is already accepted |
| Cloudflare Access + `cloudflared` | Access policy on the hostname; central accepts `Cf-Access-Authenticated-User-Email` (cloudflared talks to loopback, inside default trusted proxies) |
| Tailscale Serve | keep `AUTH_MODE=none` on tailnet-only `:8079` (identity = tailnet), or put Authentik in front as above |

## 🔍 Recon providers (attacker enrichment)

Click any IP → **Recon** auto-enriches via `RECON_PROVIDER`:

- `spiderfoot` (default): needs a reachable `SPIDERFOOT_URL`; tune with `RECON_MODULES`. Unreachable backend → clean `error` state, never blocks the UI.
- `webhook`: plug **any** probing service — POST `{"ip": "1.2.3.4"}` to `RECON_WEBHOOK_URL` (optional `RECON_WEBHOOK_TOKEN` bearer), return `{"findings": [{"type": "ASN", "data": "AS…", "module": "my-source"}]}`. Accepts `eventType`/`finding`/`value`/`info` and `source`/`provider` aliases. Results cached 7d like SpiderFoot scans.
- `none`: recon section reports disabled (no external calls at all).

### Option C — demo (any machine, 2 min, no real logs)

```bash
docker compose --profile demo up --build
# open http://localhost:8081  (sample fleet log, 10 countries, 48h)
```

Regenerate the sample data:

```bash
python3 demo/gen_auth_log.py  # writes demo/auth.log.sample (seeded, deterministic)
```

## 🌐 Fleet: central + join N servers (Tailscale recommended)

**On central:** run the `central` service as above, then mint a join token:

```bash
docker exec ssh-sentinel python3 /srv/server.py gentoken web-01
# -> host=web-01, token=..., central=http://<this-host>:8079
```

**On the joining server** (needs `tailscale status` so it can reach central by tailnet name) — pick one role runner:

```bash
# Option 1 — container agent (same image, ROLE=agent, no systemd needed)
ROLE=agent AGENT_ID=web-01 CENTRAL_URL=https://<central-tailnet-name>:8079 \
AGENT_TOKEN=<token> docker compose --profile agent up -d --build

# Option 2 — host systemd agent
git clone https://github.com/authoritydmc/ssh-sentinel.git && cd ssh-sentinel
CENTRAL_URL=http://<central-tailnet-name>:8079 AGENT_TOKEN=<token> sudo -E ./agent/install.sh
# or without clone: set AGENT_ID explicitly
CENTRAL_URL=http://central:8079 AGENT_TOKEN=<token> AGENT_ID=web-01 sudo -E ./agent/install.sh
```

Verify on central:

```bash
curl -s localhost:8079/api/hosts | python3 -m json.tool
curl -s 'localhost:8079/api/summary?host=web-01' | head -c 500
```

The UI gains a host filter (All hosts + per-host pills with online dot) once agents report.

Rotate a host: `gentoken <host>` again on central, update `/etc/ssh-sentinel-agent/env` on the member, `systemctl restart ssh-sentinel-agent`.

## 🖥️ UI tour

| View | Route state | What to do |
| ---- | ----------- | ---------- |
| **Overview** | sidebar → Overview | 6 metric cards, SSH activity trends (failed red / accepted green), auth donut, world map, top regions, top-8 attackers |
| **Attackers** | sidebar → Attackers | full top-25 table, filter by IP/user/country, click row → intel modal |
| **Intel modal** | click any IP | location, org/ASN, rDNS, RDAP, hits + first/last + users tried, 48h bars, **Show full log chain**, **Recon** (auto-start, cached 7d, re-run button) |
| **Live events** | sidebar → Live events | filter (e.g. `Accepted` or an IP), pause/resume, order toggle, 15s refresh, severity badges (attack/auth/system) |
| **Host pills** | header | `all hosts` vs per-host, hover shows last-seen, green = online (<120s) |

The UI is the React build in `dist/` (ships in Docker). Without `dist/`, unknown routes return `404`.

## 🔌 API reference

Same origin, no auth for reads (keep behind tailnet/SSO). Agent push requires bearer.

| Method | Path | Params | Notes |
| ------ | ---- | ------ | ----- |
| `GET` | `/healthz` | — | `ok` (Docker healthcheck, always open) |
| `GET` | `/api/health` | — | open liveness snapshot: status, uptime, version, mode, hosts, log/data checks (for Uptime Kuma etc.) |
| `GET` | `/oidc/login`, `/oidc/callback`, `/oidc/logout` | — | built-in SSO flow in `oidc` mode (302 redirects + session cookie) |
| `GET` | `/api/auth` | — | `{mode, login, user, safe}` — lock badge source, always open |
| `GET` | `/api/summary` | `?host=all\|<id>` | total, ips, top[25], timeline[48h], logins[60], excluded_self, hosts (login required unless `AUTH_MODE=none`) |
| `GET` | `/api/hosts` | — | `[{id, local, last_seen, online, lines}]` (login required unless `none`) |
| `GET` | `/api/tail` | `?q=&n=200&host=` | plain-text log slice, `n` clamped 10–2000, case-insensitive substring (login required unless `none`) |
| `GET` | `/api/ipinfo` | `?ip=&host=` | geo + rdap + rDNS + `history{users,hits,first,last,timeline}` (login required unless `none`) |
| `GET` | `/api/abusers` | `?host=&page=&per_page=` | **public-safe** attacker feed: ip, hits, first/last, attempted users, geo/org/ASN, flag. Paginated (≤200/page), cached 60s, rate-limited (`ABUSERS_RPM`, default 60/min/IP, `429` + `Retry-After`). **Never** exposes accepted logins, hostnames, internal/self IPs, or raw lines. Behind the login gate unless `AUTH_MODE=none` — expose intentionally (separate port/route) if you want it public |
| `POST` | `/api/recon` | `?ip=&force=` | SpiderFoot scan orchestration; `cached\|started\|running\|done\|error` (poll). `400` for private IPs / unreachable SpiderFoot (login required unless `none`) |
| `POST` | `/api/agent/push` | `Authorization: Bearer <token>` + `{"host","lines":[]}` | max 5000 lines/req, 2000 chars/line, capped at 60k lines/host |

Examples:

```bash
curl -s 'http://localhost:8079/api/summary?host=all' | python3 -m json.tool | head -n 40
curl -s 'http://localhost:8079/api/tail?q=Accepted&n=5'
curl -s 'http://localhost:8079/api/ipinfo?ip=77.91.71.90' | python3 -m json.tool | head -n 40
curl -X POST 'http://localhost:8079/api/recon?ip=77.91.71.90'
```

## ⚙️ Configuration

| Var | Default | Where | Purpose |
| --- | ------- | ----- | ------- |
| `HOST_ID` | hostname | central | Local host id in fleet view |
| `PORT` / `DEMO_PORT` | `8079` / `8081` | compose | Host port mapping |
| `SELF_PUBLIC_IPS` | `` | central | Comma-separated own public IPs to exclude from attacker stats (NAT hairpin) |
| `AUTH_LOG` | `/var/log/auth.log` | central | Live log path inside container (`/srv/demo/auth.log.sample` in demo) |
| `DATA_DIR` | `/srv/data` | central | Hosts + `agents.json` volume |
| `CENTRAL_URL` | `http://central:8079` | agent | Central base URL (use tailnet name in fleet) |
| `AGENT_TOKEN` | `` (required) | agent | Bearer from `gentoken <host>` |
| `AGENT_ID` | hostname | agent | Must match the `gentoken` host id |
| `PUSH_EVERY` | `10` | agent | Push interval seconds |
| `SPIDERFOOT_URL` | `http://spiderfoot:5001` | central | Optional recon backend; recon endpoints error gracefully if unreachable |
| `RECON_MODULES` | `sfp_dnsresolve,sfp_whois,sfp_ipapico,sfp_abusech` | central | SpiderFoot module list |
| `AUTH_MODE` | `local` | central | `local` (Basic login, fail-closed) \| `forward` (Authentik+Traefik ForwardAuth via SSO headers) \| `oidc` (built-in SSO code flow) \| `none` (open — private tailnet/demo only) |
| `AUTH_USER` | `admin` | central | Local-login username |
| `AUTH_PASS_HASH` | `` | central | `pbkdf2-sha256$…` from `docker exec ssh-sentinel python3 /srv/server.py genhash` (preferred over `AUTH_PASSWORD`) |
| `AUTH_PASSWORD` | `` | central | Plaintext fallback (never logged); prefer the hash |
| `AUTH_ALLOWED_USERS` | `` | central | Optional allowlist for forward mode, e.g. `alice,bob@example.com` |
| `AUTH_TRUSTED_PROXIES` | loopback + RFC1918 + Tailscale CGNAT | central | CIDRs allowed to present SSO identity headers (spoof-safe ForwardAuth) |
| `RECON_PROVIDER` | `spiderfoot` | central | `spiderfoot` (needs `SPIDERFOOT_URL`) \| `webhook` (POST `{ip}` to `RECON_WEBHOOK_URL`, returns `{findings:[{type,data,module}]}`) \| `none` (recon disabled) |
| `RECON_WEBHOOK_URL` / `RECON_WEBHOOK_TOKEN` | `` | central | Your intel hook (n8n, custom API…) + optional Bearer |
| `ABUSERS_RPM` | `60` | central | `/api/abusers` per-client-IP requests/minute (`429` past budget) |
| `TLS_CERT` / `TLS_KEY` | `` | central | Container paths to PEM cert/key — enables in-repo TLS 1.3-only listener (else terminate at Tailscale/Traefik) |

Files:

| Path | What |
| ---- | ---- |
| `frontend/` | Vite + React 19 + Tailwind v4 SOC dashboard (code-split) |
| `backend/server.py` | stdlib API + static dist serving + agent push + host store |
| `agent/agent.py` | stdlib trailing shipper (systemd via `install.sh`) |
| `demo/` | sample log + generator for UI work without real attacks |
| `Dockerfile` | node:20 build → python:3.12-alpine runtime |
| `.github/workflows/` | `docker.yml` (GHCR + Docker Hub publish), `ci.yml` (frontend lint/build + python compile) |

## 🔒 Security

Read [`SECURITY.md`](SECURITY.md) before exposing anything.

- Login is **fail-closed by default** (`AUTH_MODE=local`): UI + read APIs need HTTP Basic (`AUTH_USER` + `AUTH_PASS_HASH`/`AUTH_PASSWORD`); `/healthz` and `/api/auth` stay open. No credential configured → deny-all with a setup hint.
- `AUTH_MODE=forward`/`oidc` trusts SSO identity headers (`X-Forwarded-User`/`Email`, Authentik `X-authentik-username`/`X-authentik-email`, Authelia `Remote-User`, Cloudflare Access email) from Authentik-via-Traefik ForwardAuth (Dozzle-oidc pattern) **only when the connection comes from `AUTH_TRUSTED_PROXIES`** (spoof-safe); optional `AUTH_ALLOWED_USERS` allowlist; else `401`/`403`.
- `AUTH_MODE=none` is the explicit open flag for private tailnet/demo only.
- Agents push outbound only (no inbound ports on members).
- Bearer per-host tokens in `data/agents.json` (`0600`); Tailscale gives WireGuard identity + encryption. Optional in-repo TLS 1.3-only listener via `TLS_CERT`/`TLS_KEY`; agent `CENTRAL_URL=https://…` already verifies with system roots.
- **Never expose 8079 publicly without SSO in front** (Tailscale Serve / Cloudflare Access / Authelia).
- `/api/abusers` is safe-fields-only by construction (no accepted logins, hostnames, internal/self IPs, or raw lines) but stays behind the login gate unless you expose it intentionally — it is paginated, cached 60s, and rate-limited (`ABUSERS_RPM`, `429` + `Retry-After`).
- `.env` and `data/` are git-ignored; only `.env.example` ships. Tokens are runtime-minted via `secrets.token_urlsafe(32)`.
- Demo log is 100% synthetic (`demo/gen_auth_log.py`, seeded) — safe to share screenshots.

## 🛠️ Development

Agent-land rules (docs style, checks, hooks): [`AGENTS.md`](AGENTS.md).

```bash
scripts/install-hooks.sh                  # once per clone: commit-msg + pre-commit + pre-push gates
# frontend
cd frontend && npm ci && npm run dev      # vite dev
npm run build                              # tsc + vite -> dist/ (served by server.py)
npm run lint                               # oxlint

# backend (no deps)
python3 backend/server.py                  # serves :8079, reads $AUTH_LOG
AUTH_LOG=demo/auth.log.sample python3 backend/server.py

# agent
CENTRAL_URL=http://localhost:8079 AGENT_TOKEN=dummy python3 agent/agent.py

# full stack
docker compose up --build
docker compose --profile demo up --build
```

Images publish on every `master` push + tags via GitHub Actions:

- `ghcr.io/authoritydmc/ssh-sentinel:latest` (+ `:sha-<commit>`, semver on tags)
- `rajlabs/ssh-sentinel:latest` (same tags, requires `DOCKER_HUB_USERNAME` + `DOCKER_HUB_ACCESS_TOKEN` secrets)

## 📝 Changelog

See [`CHANGELOG.md`](CHANGELOG.md). License: [`MIT`](LICENSE).
