## What / why (scenario)

## Changes

- [ ] backend (`central-rs`, Rust — no Python in runtime image)
- [ ] agent
- [ ] frontend (`npm run lint` + `npm run build` clean)
- [ ] docs (README / SECURITY / CHANGELOG / `.env.example`)

## Verification

- [ ] `cargo test` for `central-rs` plus `agent-rs` (WSL)
- [ ] `./test_docker.sh` (covers open + local-auth + abusers safety)
- [ ] CI + Docker workflow runs linked below
- [ ] Docker Hub / GHCR tags checked

## Tracker

Closes / relates to #… (umbrella issue #1 for the public-ready track)
