# Rust migration report

> Style note: this document uses simplified English.
> Sentences are short. Each sentence has one idea.

## 1. Baseline (old Python image)

Measured in CI on 2026-10-07 (`footprint` job, demo log, idle):

| Metric | Value |
| ------ | ----- |
| Central image, local | 56.4 MB |
| Central image, Hub compressed | about 21 MB per arch |
| Central RSS, idle | 22.2 MiB |
| Central CPU, idle | 0.02% |
| Rust agent binary, release | 1,821,552 bytes (about 1.7 MB) |

The old image was multi-stage: node build plus `python:3.12-alpine` runtime.
The new image is node build plus cargo build plus `debian-slim` runtime.
The `footprint` job reprints fresh numbers on every run.

## 2. Layout (workspace)

One workspace at the repo root. Three crates inside.

| Crate | Binary | Role |
| ----- | ------ | ---- |
| `central-rs` | `ssh-sentinel` | API plus UI server |
| `agent-rs` | `ssh-sentinel-agent` | Log shipper |
| `tools/make-icons` | `make-icons` | Dev-only icon renderer, never shipped |

All crates use edition 2024. Versions track the repo `VERSION` file.
Build all with `cargo build --workspace`. Test all with `cargo test --workspace`.

## 3. Install from cargo

From source (needs a Rust toolchain):

```bash
cargo install --git https://github.com/authoritydmc/ssh-sentinel ssh-sentinel
cargo install --git https://github.com/authoritydmc/ssh-sentinel ssh-sentinel-agent
```

From crates.io after the first publish:

```bash
cargo install ssh-sentinel
cargo install ssh-sentinel-agent
```

Publish howto for the owner: `cargo login`, then
`cargo publish -p ssh-sentinel-agent`, then `cargo publish -p ssh-sentinel`.
CI already runs `cargo publish --dry-run` for both crates on every PR.

## 4. Native release binaries

Every tag builds both binaries for four targets. Assets attach
to the GitHub Release automatically. Names carry the target triple:

| Target | Runner | Asset suffix |
| ------ | ------ | ------------ |
| `x86_64-unknown-linux-musl` | ubuntu | static, runs anywhere |
| `x86_64-pc-windows-msvc` | windows | plus `.exe` |
| `aarch64-apple-darwin` | macOS arm | Apple Silicon |
| `x86_64-apple-darwin` | macOS Intel | Intel Macs |

Linux members use `agent/install.sh`. It fetches the musl asset.
macOS and Windows users download the asset and run it directly.

## 5. Versions and tags

Tags are always semver (`vX.Y.Z` via `scripts/release.sh`). No date tags.
Docker tags follow the release: `X.Y.Z`, `X.Y`, `latest`, `prod.<sha>`.
Crate versions track the repo `VERSION` file. Bump them with each release.

## 6. Swap record (central in Rust)

Python is gone from code, image, and CI (only release history mentions it).

- `central-rs` serves the API plus UI. Same routes, same DB schema.
- `agent-rs` ships logs. Static musl binary in GitHub Releases.
- The image holds no Python and no build tools.
- Equivalence was proven before the swap (Python versus Rust diff, all green).
- Post-swap safety comes from `cargo test` plus `smoke-central.sh` in CI.

## 7. Post-swap numbers (v0.7.1, measured in CI)

| Metric | Python era | Rust now |
| ------ | ---------- | -------- |
| Central image, local | 56.4 MB | 94.6 MB |
| Central image, Hub compressed | about 21 MB per arch | about 36 MB per arch |
| Central RSS, idle | 22.2 MiB | 1.85 MiB |
| Central CPU, idle | 0.02% | 0.00% |
| Standalone agent image | n/a (shared image) | 3.3 MB on `scratch` |

Read it plainly. The image grew. Debian plus certs cost more
than Alpine plus Python. Runtime RAM fell 12x. The agent
image is tiny. RAM wins. Image size does not.

To shrink the image next: replace `debian-slim` with a smaller
base that still ships `getent` for rDNS, or drop the PTR lookup.
That choice is open. It needs its own test round.


## 8. Production snapshot (sanitized, v0.7.4)

Live two-host fleet, central plus one remote agent. No host names,
addresses, URLs, or tokens are recorded here on purpose.

| Metric | Value |
| ------ | ----- |
| Central CPU, loaded | 0.00% |
| Central RSS, loaded | about 42 MiB (256 MiB container limit) |
| Load at measure time | about 9 MB auth log, 2 hosts, 260+ geo entries cached, 500+ tracked IPs |
| Agent RSS | about 0.8 MiB (Python shipper: 4.7 MiB, 17.5 MiB peak) |
| `GET /api/summary` | 1-5 ms (Python era: 7-58 ms, measured on a smaller log) |

Read it as: image got fatter (Alpine plus Python beat slim plus Rust
on bytes), runtime got leaner everywhere else. Idle CI numbers above
stay the reference for cross-version comparison.
