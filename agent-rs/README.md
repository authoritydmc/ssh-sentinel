# SSH Sentinel agent in Rust

Small static binary. Ships auth log lines to central over HTTPS plus Bearer.

## Build

```bash
cargo build --release -p ssh-sentinel-agent
# binary: target/release/ssh-sentinel-agent
```

Or install from git: `cargo install --git https://github.com/authoritydmc/ssh-sentinel ssh-sentinel-agent`.
Release binaries for Linux, Windows, and macOS attach to every GitHub Release.

Static musl image:

```bash
docker build -f agent-rs/Dockerfile -t ssh-sentinel-agent-rs .
```

## Run

```bash
CENTRAL_URL=http://central:8079 AGENT_TOKEN=<token> AGENT_ID=web-01 \
  AUTH_LOG=/var/log/auth.log PUSH_EVERY=10 \
  ./ssh-sentinel-agent
```

State lives in `AGENT_STATE` (default `/var/lib/ssh-sentinel-agent/state.json`).
Shape: `{"ino": 123, "offset": 456}`. The offset survives restarts.

## Behavior spec

| Area | Rule |
| ---- | ---- |
| Env names and defaults | `CENTRAL_URL`, `AGENT_TOKEN`, `AGENT_ID`, `AUTH_LOG`, `PUSH_EVERY=10`, `AGENT_STATE`, `SHIP_FILTER=sshd-only` |
| `SHIP_FILTER=sshd-only` | Ship lines with `sshd` or `pam_unix(sshd` substring |
| Accepted lines | Always shipped fully (IP plus user) |
| Push | `POST {CENTRAL}/api/agent/push`, Bearer token, JSON `{host, lines}` |
| Batch cap | Last 2000 lines per push |
| Backoff | 5s doubling to 300s on push failure |
| Truncated file | Offset resets to zero |
| Bad PUSH_EVERY | Falls back to 10 |

TLS uses rustls with built-in roots. No system certs needed.
The `scratch` image therefore works for `https://` central URLs too.

## Verify

```bash
AGENT_BIN=target/release/ssh-sentinel-agent CENTRAL_BIN=target/debug/ssh-sentinel bash scripts/smoke-agent.sh
```

CI runs this on every PR (job `rust-agent` in `ci.yml`).
