# SSH Sentinel agent in Rust (pilot)

Small static binary with the same push protocol as `agent-rs`.
Use it where the Python agent feels heavy. Central stays Python.

## Build

```bash
cargo build --release --manifest-path agent-rs/Cargo.toml
# binary: agent-rs/target/release/ssh-sentinel-agent
```

Static musl image:

```bash
docker build -f agent-rs/Dockerfile -t ssh-sentinel-agent-rs .
```

## Run

Same env vars as the Python agent:

```bash
CENTRAL_URL=http://central:8079 AGENT_TOKEN=<token> AGENT_ID=web-01 \
  AUTH_LOG=/var/log/auth.log PUSH_EVERY=10 \
  ./ssh-sentinel-agent
```

State lives in `AGENT_STATE` (default `/var/lib/ssh-sentinel-agent/state.json`).
Format matches Python: `{"ino": 123, "offset": 456}`. Both agents can share it.

## Parity with Python

| Area | Status |
| ---- | ------ |
| Env names and defaults | Same |
| `SHIP_FILTER=sshd-only` rule | Same (`sshd` or `pam_unix(sshd` substring) |
| Accepted lines shipped fully | Same |
| Push URL, Bearer, JSON shape, User-Agent | Same |
| Last 2000 lines per push | Same |
| Backoff 5s doubling to 300s | Same |
| Truncated file | Rust resets offset, Python keeps stale offset |
| Bad PUSH_EVERY | Rust falls back to 10, Python exits at startup |

TLS uses rustls with built-in roots. No system certs needed.
The `scratch` image therefore works for `https://` central URLs too.

## Verify

```bash
AGENT_BIN=agent-rs/target/release/ssh-sentinel-agent bash scripts/parity-agent.sh
```

CI runs this on every PR (job `rust-agent` in `ci.yml`).
