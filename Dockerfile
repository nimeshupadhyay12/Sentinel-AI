# ==========================================
# Stage 1: Build Frontend (Vite + React)
# ==========================================
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ==========================================
# Stage 2: Python backend serving API + built SPA
# ==========================================
FROM python:3.11-slim
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# curl is used only by the HEALTHCHECK below.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install -r ./backend/requirements.txt

COPY backend/ ./backend/
COPY research/results/ ./research/results/
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Run as an unprivileged user. Application code stays root-owned and read-only
# for that user; only /app/data (SQLite fallback, mount a volume here) is writable.
RUN groupadd --system --gid 10001 sentinel \
    && useradd --system --uid 10001 --gid sentinel --no-create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /app/data && chown sentinel:sentinel /app/data
USER sentinel

WORKDIR /app/backend
# The runtime user has no home directory: point library caches at /tmp.
ENV PYTHONPATH=/app/backend \
    PORT=8000 \
    DATABASE_URL=sqlite:////app/data/sentinelai.db \
    MPLCONFIGDIR=/tmp/matplotlib \
    NUMBA_CACHE_DIR=/tmp/numba-cache

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8000}/health" || exit 1

# --proxy-headers makes request.client.host the real client IP behind the
# platform's reverse proxy, which the per-IP login throttle relies on. Only keep
# FORWARDED_ALLOW_IPS='*' when the container is reachable solely via that proxy.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips=\"${FORWARDED_ALLOW_IPS:-*}\""]
