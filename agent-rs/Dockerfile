# SSH Sentinel Rust agent: static musl binary on scratch.
# Same push protocol as agent-rs. Configure via env (see README).
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev gcc cmake perl
WORKDIR /build
COPY agent-rs/Cargo.toml ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
  && cargo build --release || true
COPY agent-rs/ ./
# COPY keeps old mtimes, so cargo would call the dummy build fresh.
# Touch sources first to force a real rebuild.
RUN find src -exec touch {} + \
  && cargo build --release \
  && cp "$(ls target/*/release/ssh-sentinel-agent | head -1)" /agent-bin \
  && ls -l /agent-bin

FROM scratch
COPY --from=build /agent-bin /agent
ENTRYPOINT ["/agent"]
