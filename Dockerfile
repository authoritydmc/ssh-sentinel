# SSH Sentinel: React SOC dashboard (built) + stdlib Python API (runtime).
FROM node:26-alpine AS web
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-alpine
ARG APP_VERSION=dev
ARG GIT_COMMIT=unknown
LABEL org.opencontainers.image.title="ssh-sentinel" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}"
ENV APP_VERSION=${APP_VERSION} GIT_COMMIT=${GIT_COMMIT}
WORKDIR /srv
COPY backend/server.py ./server.py
COPY --from=web /build/dist ./dist
EXPOSE 8079
CMD ["python3", "/srv/server.py"]
