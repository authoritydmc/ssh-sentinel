---
name: rust-wsl
description: Compile, check, and test all Rust code through WSL. Use for any Rust build, cargo check, cargo test, or binary run in this repo.
---

# Rust via WSL skill

## Rule

Windows has no Rust toolchain. Use WSL Ubuntu for every Rust command.
Never try Windows-native `cargo` or `rustc`. They do not exist here.

## Environment

- WSL distro is Ubuntu on WSL2. `wsl` runs commands there.
- Cargo lives at `~/.cargo/bin/cargo`. It is not on PATH.
- Rustc lives at `~/.cargo/bin/rustc`. Same PATH note.
- Repo root maps to `/mnt/d/coding/ssh-sentinel` inside WSL.
- C++ compiler is present (`g++` 13). Perl is present.
- CMake is missing. `sudo` needs an interactive password.
- Prefer crates that build without CMake. Check before you add a dep.

## Commands

Prefix every Rust command with the full cargo path:

```bash
wsl ~/.cargo/bin/cargo --version
wsl ~/.cargo/bin/cargo check --manifest-path /mnt/d/coding/ssh-sentinel/agent-rs/Cargo.toml
wsl ~/.cargo/bin/cargo test --manifest-path /mnt/d/coding/ssh-sentinel/agent-rs/Cargo.toml
wsl ~/.cargo/bin/cargo build --release --manifest-path /mnt/d/coding/ssh-sentinel/central-rs/Cargo.toml
```

Run built binaries from WSL too:

```bash
wsl /mnt/d/coding/ssh-sentinel/agent-rs/target/debug/ssh-sentinel-agent
```

## Notes

- Quote paths with spaces. None exist in this repo.
- WSL sees Windows files live. No copy step is needed.
- Line endings stay LF. Do not commit CRLF in `.rs` or `.sh` files.
- If a build needs CMake, stop and ask the owner to install it.
- CI (job `rust-agent`) repeats the same build plus tests on Ubuntu.
