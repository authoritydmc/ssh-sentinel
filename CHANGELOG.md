# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.7.4] - 2026-10-07

## [0.7.3] - 2026-10-07

## [0.7.2] - 2026-10-07

### Fixed
- Fleet online status: central wrote agent sidecars as `<id>.jsonl.meta` but read `<id>.meta`,
  so every pushing agent showed offline forever. Writers now use the canonical `<id>.meta` path
  and the reader falls back to the legacy name.

## [0.7.1] - 2026-10-07

## [0.7.0] - 2026-10-07

### Added
- Gallery in README with 8 masked screenshots. Only attacker data shows.
  Log-line shots stay out: raw lines carry the node host name.
- Rust runtime for central plus agent. No Python in code, image, or CI.
  `central-rs` serves the API plus UI. `agent-rs` ships logs.
  Same API, same DB schema, same CLI (`gentoken`, `genhash`, `scrub`).
- Cargo workspace at the repo root. Crates carry repo version plus metadata.
  Install with `cargo install --git https://github.com/authoritydmc/ssh-sentinel`.
  Crates.io publish is ready (`cargo publish --dry-run` runs in CI).
- Native release binaries for Linux, Windows, and macOS on every tag.
  `agent/install.sh` fetches the matching static Linux binary.
- CI covers the swap: `cargo test`, agent smoke, central smoke,
  musl static build, standalone agent image build.
- `PORT` env selects the listen port (default 8079).
- Full sign-in panel: mode-aware help plus always-visible SSO button in `oidc` mode.
- Rust agent (`agent-rs/`): static musl image, smoke-tested in CI.
- Rust central (`central-rs/`): unit-tested (RFC 7515 vector included).
- CI footprint job: reports central image size plus RSS plus CPU on every run. See `docs/RUST_MIGRATION.md`.
- Docker smoke test asserts UI serving (shell, bundle, SPA fallback) and
  captures a headless dashboard screenshot as a CI artifact.
- Admin can edit bans and reports from UI. New `GET plus POST /api/admin/config` stores overrides in SQLite. Env var set locks a field. No restart is needed.
- Admin can edit whitelist, trusted IPs and users, self IPs, abusers bar, and public feed from UI. Same env-lock rule applies.
- Fail2ban guide `docs/FAIL2BAN.md` with same-host push plus banlist pull plus verify steps. Linked from Admin, README, and `.env.example`.
- Top regions show flags plus country plus hits. World map shows counts plus hottest origin plus top 6 list.
- Accepted logins hide full IP in masked mode. Attacker IPs keep partial mask.

### Fixed
- Ban list shows created plus remaining plus firewall state. Expires text explains monitor-only mode.
- Bytecode never ships: `.gitignore` plus `.dockerignore` cover caches, local DBs, and `target/`. LF endings enforced via `.gitattributes`.

## [0.6.0] - 2026-10-07

### Added
- Log source + retention (issue #26): `LOG_SOURCE=file|journald` (journald reads `journalctl _COMM=sshd -o short-iso`), `RETENTION_DAYS` prunes stored host lines older than N days on push.
- Attackers UX (issue #27): ASN column + CSV export on the Attackers view; search filter already present; IPv6 fully supported in parse/mask/filter.

## [0.5.0] - 2026-10-07

### Added
- Login + spike alerting (issue #25): `ALERT_WEBHOOK_URL` (+ optional `ALERT_WEBHOOK_TOKEN`, falls back to abuse webhook) posts `login.suspicious` and `spike.bruteforce` events from `/api/summary`, with `ALERT_ON_SUCCESS` / `ALERT_SPIKE_THRESHOLD` / `ALERT_SPIKE_WINDOW_S` / `ALERT_DEDUPE_S` tuning and `POST /api/alerts/test` for checks.

## [0.4.0] - 2026-10-07

### Added
- About dialog: footer version button opens version, short commit, and full changelog (`GET /api/version`, always open). `VERSION` + `CHANGELOG.md` now ship inside the image. `auth_status` and `/api/health` fall back to the `VERSION` file when `APP_VERSION` is unset.
- Bundled SpiderFoot OSINT for recon: compose `--profile recon` starts `spiderfoot/spiderfoot:latest` (loopback UI, persisted volume). Central wires `SPIDERFOOT_URL` + `RECON_MODULES` automatically. Unreachable backend now reports the exact URL plus the start command.
- Built-in SSO (`AUTH_MODE=oidc`): authorization-code flow against any OIDC provider (Authentik tested pattern), RS256 ID-token verify, server sessions, `/oidc/logout`, UI "Sign in with SSO" button. Covered by `scripts/selftest_oidc.py` (RFC 7515 vector, runs in CI).
- Open `/api/health` for uptime monitors (status, uptime, version, mode, hosts, log/data checks); `/healthz` stays plain `ok`.
- Removed the legacy single-file `PAGE` fallback (React `dist/` is the only UI; missing build returns `404`).
- Risk-scored public list: `abusers()` lists repeat offenders only (≥`ABUSERS_MIN_HITS`, score ≥`ABUSERS_MIN_SCORE`, auto-excluded on any successful login), each entry with risk/band/reasons, optional AbuseIPDB confidence. `ABUSERS_PUBLIC=1` opens `/api/abusers` + a public `/abusers` leaderboard without login.
- `WHITELIST_IPS` removes admin/owner IPs from every attacker list; open `/api/self` reports each visitor's own status and the UI warns listed visitors to ask for whitelisting.
- Fail2ban bans + auto-block + admin panel + SQLite risk store + abuse reports (issue #19): `POST /api/admin/ban|unban`, `GET /api/admin/bans|activity|reports`, `GET /api/banlist`, first-setup wizard (`POST /api/admin/setup` with one-time token), password change, ban buttons in intel modal, Admin view (bans/reports/activity/settings), hammer auto-ban loop (`BAN_AUTO`, `BAN_THRESHOLD/WINDOW`), velocity + repeat-ban risk signals, AbuseIPDB + webhook reports with per-provider throttle, `examples/fail2ban-action.conf`. Backend stays stdlib-only.
- GHCR images now carry SLSA build provenance (`actions/attest-build-provenance`, Sigstore-signed). Verify with `gh attestation verify oci://ghcr.io/<owner>/ssh-sentinel --owner <owner>`.
- Screenshot-safe UI: header **mask** toggle (off by default, per-browser memory) hides IPs, usernames, host names, and session lines on every page. Accepted usernames are now masked in every mode (suspicious accepts stay fully visible unless the toggle is on). The suspicious banner starts minimized when nothing changed, gains Clear/Minimize, and moved below the charts. Gallery screenshots removed.
- Brand mark: `frontend/public/logo.svg` (shield + pulse + keyhole) used in sidebar, favicon set (SVG, ICO, PNG), Apple touch icon, README header. `scripts/make-icons.py` renders the PNGs.

### Fixed
- `AUTH_MODE=forward` accepts Authentik `X-authentik-username` / `X-authentik-email` identity headers. The edge passes these names. Old code ignored them. All edge requests failed with 401.
- First-setup login with a custom user failed. `AUTH_USER` defaulted to `admin` and hid the file-based user. Every setup user got 401. Env value now wins only when set.

## [0.3.0] - 2026-10-06

### Added
- Login on the main page: `AUTH_MODE=local` (default, fail-closed HTTP Basic via `AUTH_USER` + `AUTH_PASS_HASH`/`AUTH_PASSWORD`, `server.py genhash` minter) | `forward`/`oidc` (Authentik-via-Traefik ForwardAuth identity + optional `AUTH_ALLOWED_USERS`) | `none` (explicit open flag for private tailnet/demo). `/healthz` + `/api/auth` stay open; UI shows lock badge + 401 sign-in banner.
- Public-safe `GET /api/abusers`: attacker IPs with hits, first/last, attempted users, geo/org/ASN — never accepted logins, hostnames, internal/self IPs, or raw lines. Paginated (≤200/page), cached 60s, rate-limited per client IP (`ABUSERS_RPM`, `429` + `Retry-After`).
- Optional in-repo TLS 1.3-only listener (`TLS_CERT`/`TLS_KEY`); agent push already speaks https with system-root verification.
- Fleet scope UX overhaul: explicit Fleet + per-host scope bar (central `main` badge, online-first, offline last-seen), scope-aware subtitles/footers, sticky status bar; fixed host-switch refetch stall.
- Agent `SHIP_FILTER=sshd-only` allowlist (client + server side) + `scrub` for old noise.
- SSO hardening + one-shot connect: `AUTH_TRUSTED_PROXIES` (spoof-safe header trust; loopback + RFC1918 + Tailscale default), Authelia `Remote-User` + Cloudflare Access email headers, `examples/sso-traefik-authentik.yml` overlay + provider table.
- Pluggable recon: `RECON_PROVIDER=spiderfoot|webhook|none` (`RECON_WEBHOOK_URL/TOKEN`, 7d cache) for any probing service.
- Release automation: `scripts/release.sh` (VERSION + CHANGELOG + tag + push), semver Docker tags to Hub + GHCR, GitHub Releases from CHANGELOG, issue/PR templates, Dependabot.
- Role-switchable image: `ROLE=central|agent` via `docker/entrypoint.sh` + `compose --profile agent` (container shipper alternative to systemd).
- UI: GitHub repo link with version badge (sidebar + footer, from `/api/auth`), crisp opaque metric values (blur fix).
- `docs/ARCHITECTURE.md` (mermaid + procedures), `AGENTS.md` repo rules, `.githooks/` (commit-msg, pre-commit, pre-push) + `scripts/install-hooks.sh`.
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
