# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
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
