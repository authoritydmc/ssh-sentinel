# SSH Sentinel: React SOC dashboard (built) + Rust central + Rust agent.
FROM node:26-alpine AS web
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM rust:1-bookworm AS rust
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY central-rs/Cargo.toml central-rs/
COPY agent-rs/Cargo.toml agent-rs/
RUN mkdir -p central-rs/src agent-rs/src \
  && echo 'fn main() {}' > central-rs/src/main.rs \
  && echo 'fn main() {}' > agent-rs/src/main.rs \
  && cargo build --release -p ssh-sentinel -p ssh-sentinel-agent
COPY central-rs/ central-rs/
COPY agent-rs/ agent-rs/
# COPY keeps old mtimes, so cargo would call the dummy build fresh.
# Touch sources first to force a real rebuild.
RUN find central-rs/src agent-rs/src -exec touch {} + \
  && cargo build --release -p ssh-sentinel -p ssh-sentinel-agent \
  && ls -l target/release/ssh-sentinel target/release/ssh-sentinel-agent

FROM debian:bookworm-slim
ARG APP_VERSION=dev
ARG GIT_COMMIT=unknown
LABEL org.opencontainers.image.title="ssh-sentinel" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}"
ENV APP_VERSION=${APP_VERSION} GIT_COMMIT=${GIT_COMMIT}
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY --from=rust /build/target/release/ssh-sentinel ./ssh-sentinel
COPY --from=rust /build/target/release/ssh-sentinel-agent ./ssh-sentinel-agent
COPY docker/entrypoint.sh ./entrypoint.sh
COPY VERSION ./VERSION
COPY CHANGELOG.md ./CHANGELOG.md
COPY --from=web /build/dist ./dist
RUN chmod +x /srv/entrypoint.sh /srv/ssh-sentinel /srv/ssh-sentinel-agent
EXPOSE 8079
# ROLE=central (API + UI) | agent (log shipper). See docker-compose.yml.
ENTRYPOINT ["/srv/entrypoint.sh"]
