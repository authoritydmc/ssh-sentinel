# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Login on the main page: `AUTH_MODE=local` (default, fail-closed HTTP Basic via `AUTH_USER` + `AUTH_PASS_HASH`/`AUTH_PASSWORD`, `server.py genhash` minter) | `forward`/`oidc` (Authentik-via-Traefik ForwardAuth identity + optional `AUTH_ALLOWED_USERS`) | `none` (explicit open flag for private tailnet/demo). `/healthz` + `/api/auth` stay open; UI shows lock badge + 401 sign-in banner.
- Public-safe `GET /api/abusers`: attacker IPs with hits, first/last, attempted users, geo/org/ASN — never accepted logins, hostnames, internal/self IPs, or raw lines. Paginated (≤200/page), cached 60s, rate-limited per client IP (`ABUSERS_RPM`, `429` + `Retry-After`).
- Optional in-repo TLS 1.3-only listener (`TLS_CERT`/`TLS_KEY`); agent push already speaks https with system-root verification.
- Public-release hardening: MIT LICENSE, SECURITY.md, expanded `.gitignore` / `.dockerignore`.
- GitHub Actions: Docker publish to GHCR + Docker Hub, frontend CI (lint/build).
- `SPIDERFOOT_URL` / `RECON_MODULES` env overrides (was hardcoded SpiderFoot host).
- Generic defaults (`http://central:8079`) instead of infra-specific hostnames.

## [0.2.0] - 2026-10-06

### Added
- Multi-host fleet: agent push API (`POST /api/agent/push`, bearer per-host tokens).
- `agent/agent.py` stdlib shipper (inode+offset resume, backoff) + `agent/install.sh` systemd unit.
- Host filter UI (All hosts + per-host, online dot via 120s last-seen).
- `server.py gentoken <host>` join-token minting (`data/agents.json`, 0600).
- Demo profile: `docker compose --profile demo up` with synthetic 48h / 10-country log.

## [0.1.0] - 2026-10-06

### Added
- Initial release: stdlib Python API + static React dist serving.
- Vite + React 19 + Tailwind v4 SOC dashboard (overview / attackers / live events).
- Attack intel: 48h timeline, top attackers, geo (ip-api), RDAP, rDNS, SpiderFoot recon (optional).
- Single-server `docker compose up` from live `/var/log/auth.log`.
- `GET /api/summary`, `/api/hosts`, `/api/tail`, `/api/ipinfo`, `POST /api/recon`.
