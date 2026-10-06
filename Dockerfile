# SSH Sentinel: React SOC dashboard (built) + stdlib Python API (runtime).
FROM node:20-alpine AS web
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-alpine
WORKDIR /srv
COPY backend/server.py ./server.py
COPY --from=web /build/dist ./dist
EXPOSE 8079
CMD ["python3", "/srv/server.py"]
