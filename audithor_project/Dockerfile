# =========================
# Stage 1: build sslscan
# =========================
FROM debian:bookworm-slim AS sslscan-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    git make gcc libssl-dev zlib1g-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/rbsec/sslscan.git /tmp/sslscan \
 && make -C /tmp/sslscan static

# =========================
# Stage 2: runtime (python)
# =========================
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080 \
    HEADLESS=1 \
    DATA_DIR=/data

# Paquetes runtime mínimos
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copiamos el binario estático de sslscan
COPY --from=sslscan-builder /tmp/sslscan/sslscan /usr/local/bin/sslscan

WORKDIR /app

# Dependencias primero (cache de capas)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir gunicorn

# Código de la app
COPY . .

# Usuario no root
RUN useradd -m -u 10001 appuser \
 && mkdir -p /data \
 && chown -R appuser:appuser /app /data
USER appuser

EXPOSE 8080

# Healthcheck contra /api/health (el ALB puede usar esta misma ruta)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/api/health || exit 1

# Defaults para Opción A: un solo worker (un único proceso = un único diccionario JOBS)
# Ajusta con variables de la Task Definition si lo necesitas.
ENV GUNICORN_WORKERS=1 \
    GUNICORN_THREADS=8 \
    GUNICORN_TIMEOUT=3600 \
    PORT=8080

# Arranque: un worker + gthread (afinidad del ALB mantendrá al cliente en el mismo target)
CMD ["sh","-c","gunicorn -w ${GUNICORN_WORKERS:-1} -k gthread --threads ${GUNICORN_THREADS:-8} --timeout ${GUNICORN_TIMEOUT:-3600} -b 0.0.0.0:${PORT:-8080} audithor_app:app"]
