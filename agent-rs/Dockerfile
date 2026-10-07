# SSH Sentinel Rust agent: static musl binary on scratch.
# Same push protocol as agent-rs. Configure via env (see README).
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev gcc cmake perl
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY agent-rs/Cargo.toml agent-rs/
COPY central-rs/Cargo.toml central-rs/
COPY tools/make-icons/Cargo.toml tools/make-icons/
RUN mkdir -p agent-rs/src \
  && echo 'fn main() {}' > agent-rs/src/main.rs \
  && cargo build --release -p ssh-sentinel-agent || true
COPY agent-rs/ agent-rs/
# COPY keeps old mtimes, so cargo would call the dummy build fresh.
# Touch sources first to force a real rebuild.
RUN find agent-rs/src -exec touch {} + \
  && cargo build --release -p ssh-sentinel-agent \
  && cp "$(find target -name ssh-sentinel-agent -type f | head -1)" /agent-bin \
  && ls -l /agent-bin

FROM scratch
COPY --from=build /agent-bin /agent
ENTRYPOINT ["/agent"]
