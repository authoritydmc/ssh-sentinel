# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| `latest` Docker tag / `master` branch | ✅ |
| Older tags | Best-effort, please upgrade |

## Reporting a vulnerability

Open a GitHub Security Advisory or issue with:

1. Affected version / image digest
2. Steps to reproduce
3. Impact assessment

Do **not** open a public issue with exploit details for RCE / auth bypass.
Prefer a private advisory; we aim to respond within 72h.

## Deployment hardening (read before exposing)

SSH Sentinel is designed to run on a **private tailnet or localhost**:

- Agents push **outbound only** (no inbound ports on members).
- Bearer per-host tokens are stored in `data/agents.json` (`0600`).
  Rotate with `docker exec ssh-sentinel python3 /srv/server.py gentoken <host>`.
- **Never expose port 8079 directly to the internet.** Put SSO in front
  (Tailscale Serve, Cloudflare Access, Authelia, Traefik + Authentik).
- Treat `AGENT_TOKEN` like a password: pass via env / secret store,
  never commit to git, never paste in screenshots.
- `SELF_PUBLIC_IPS` excludes your own scanners/VPN egress from attacker stats.
- Demo data (`demo/auth.log.sample`) is fully synthetic — safe to share.

## What's safe to publish

- This repo contains **no credentials, private keys, or customer data**.
  Gate checks: `.env` is git-ignored, only `.env.example` is committed,
  `data/` is git-ignored, tokens are generated at runtime via `secrets.token_urlsafe`.
