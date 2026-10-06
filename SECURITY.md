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
- **Login modes** (`AUTH_MODE`, default `local` fail-closed): `local` = HTTP Basic
  against `AUTH_USER` + `AUTH_PASS_HASH` (mint with `server.py genhash`) or
  `AUTH_PASSWORD`;   `forward` = trust SSO identity headers from
  Authentik-via-Traefik ForwardAuth (Authentik `X-authentik-username` / `X-authentik-email`, also Authelia `Remote-User`, Cloudflare
  Access email) **only from `AUTH_TRUSTED_PROXIES`** (default loopback +
  RFC1918 + Tailscale), with optional `AUTH_ALLOWED_USERS`;
- **Built-in SSO** (`AUTH_MODE=oidc`): authorization-code flow against
  `OIDC_ISSUER` with RS256 ID-token verify (issuer, audience, expiry,
  nonce), state/nonce anti-replay, server-side sessions (random token in
  HttpOnly cookie, `OIDC_SESSION_TTL`), optional `AUTH_ALLOWED_USERS`.
  RS256 check is stdlib-only and covered by `scripts/selftest_oidc.py`
  (RFC 7515 vector); set `OIDC_COOKIE_SECURE=1` on direct HTTPS;
  `none` = explicit open mode for private networks/demo only. `/healthz` and
  `/api/auth` stay open; agent push keeps its own per-host Bearer tokens.
- **`/api/abusers`** exposes attacker IPs only (hits, first/last, attempted
  users, geo/org/ASN) — accepted logins, hostnames, internal/self IPs and raw
  lines can never appear. Still gated by login unless `AUTH_MODE=none`;
  paginated, cached 60s, rate-limited per client IP.
- Treat `AGENT_TOKEN` like a password: pass via env / secret store,
  never commit to git, never paste in screenshots.
- **First setup** (`AUTH_MODE=local` with no credential): the server mints
  a one-time token (`ADMIN_SETUP_TOKEN` env or `data/setup.token`, `0600`,
  printed once in the log). `POST /api/admin/setup` with that token creates
  the admin login (`data/admin.json`, `0600`, pbkdf2-sha256). Setup closes
  after first success. Env credential skips the wizard.
- **Admin APIs** (`/api/admin/*`, `/api/banlist`) always need login. Ban
  endpoints refuse private, reserved, self, and whitelisted IPs.
- `SELF_PUBLIC_IPS` excludes your own scanners/VPN egress from attacker stats.
- Demo data (`demo/auth.log.sample`) is fully synthetic — safe to share.

## What's safe to publish

- This repo contains **no credentials, private keys, or customer data**.
  Gate checks: `.env` is git-ignored, only `.env.example` is committed,
  `data/` is git-ignored, tokens are generated at runtime via `secrets.token_urlsafe`.

## Auth-log privacy (no blind masking)

`auth.log` contains more than attacker IPs: `Accepted` lines enumerate real
accounts + admin source IPs, and `sudo` lines leak `PWD`/`COMMAND` args.
Defaults are chosen so compromise detection never goes blind:

- **Allowlist at ingest** (`SHIP_FILTER=sshd-only`, default on agent + central):
  only `sshd` + `pam_unix(sshd:session)` lines are shipped/stored/served.
  `sudo`/`CRON`/`systemd` noise is dropped. `SHIP_FILTER=full` for debugging.
- **Attacker IPs always fully visible** — no masking on failed/probe stats,
  map, tables, or log chains. No PII redaction there by design.
- **Accepted usernames always masked**: normal `Accepted` logins show
  `d****y`-style names in every mode. Raw names never reach the API.
  `fail-then-accept` (IP had prior fails) is always `suspicious`;
  with `TRUSTED_IPS`/`TRUSTED_USERS` set, unknown-IP/user accepts are also
  `suspicious`. Suspicious entries show **full user + full IP** + red banner.
- **Screenshot-safe mask toggle** (header, off by default, remembered per
  browser): hides IPs, usernames, host names, and session lines on every
  page, including suspicious rows. Raw values stay in props and API calls.
  Only rendered text is masked.
- `PRIVACY_MODE=strict` additionally masks the `self_ips` list.
- Set `TRUSTED_IPS` (admin/home/runner IPs) + `TRUSTED_USERS` (e.g. `ubuntu,deploy`)
  for strongest signal. Without them, only `fail-then-accept` flags.
- Stored agent logs are `0600` plaintext JSONL capped at `MAX_LINES_PER_HOST`.
  After enabling filtering, purge old noise:
  `docker exec ssh-sentinel python3 /srv/server.py scrub`.
