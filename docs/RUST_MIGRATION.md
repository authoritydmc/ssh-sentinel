# Rust migration report

> Style note: this document uses simplified English.
> Sentences are short. Each sentence has one idea.

## 1. Baseline (Python today)

Image sizes come from Docker Hub (`rajlabs/ssh-sentinel`):

| Tag | Arch | Compressed |
| --- | --- | ---------- |
| `latest` (v0.6.0 era) | amd64 | about 21 MB |
| `latest` (v0.6.0 era) | arm64 | about 22 MB |

The image is already multi-stage: node build plus `python:3.12-alpine` runtime.
RAM and CPU are not measured yet. No Docker runs on the dev box.
The new `footprint` CI job prints image size plus RSS plus CPU on every run.
Use its output as the live baseline.

## 2. What moved to Rust

The agent moved first. It is 114 lines of Python.
The Rust pilot (`agent-rs/`) keeps full protocol parity.
Central stays Python. No API change. No behavior change.

Why the agent first:

- Small blast radius. One file. No auth logic.
- Same env vars. Same state file. Drop-in swap.
- Static musl binary runs on `scratch`. No interpreter. No certs needed.

## 3. Comparison method

1. Read the `footprint` job summary for central size plus RSS.
2. Read the `rust-agent` job log for binary size plus parity result.
3. Build the Rust agent image (`agent-rs/Dockerfile`). Compare sizes.
4. Run both agents against one central. Compare RSS via `docker stats`.

## 4. Expected gains (honest estimates)

- Rust agent binary: about 2 to 5 MB (rustls embeds crypto).
- Rust agent image: about 5 to 10 MB on `scratch`.
- Python agent shares the 21 MB central image. Standalone it needs Python (~15 MB slim).
- RSS saving: tens of MB per agent host. Matters on tiny nodes only.
- Central rewrite would save more, but costs a full rewrite of 3,044 lines.

## 5. Risks of a central rewrite

- Auth gates are subtle. Four modes. Fail-closed defaults.
- OIDC uses a hand-rolled RS256 verify. A rewrite must preserve it exactly.
- Log parsing has syslog plus ISO edge cases. Drift hides attacks.
- SQLite store plus ban plus report flows need full retesting.
- Two codebases need dual maintenance during migration.

## 6. Decision gates for Phase 3 (central in Rust)

1. Footprint data shows real pain on target hosts.
2. Rust agent runs clean in production for one release.
3. Parity harness covers all four auth modes plus abusers safety.
4. Owner accepts dual maintenance cost.

Until all four hold, central stays Python.
