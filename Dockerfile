FROM python:3.12-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libffi-dev \
        gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ssl_domain_checker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ─── Runtime stage ─────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN addgroup --system --gid 1000 vigil && \
    adduser --system --uid 1000 --gid 1000 vigil --home /app

# Copy built dependencies from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Copy application code
COPY ssl_domain_checker /app/ssl_domain_checker
COPY gunicorn.conf.py /app/gunicorn.conf.py

# Create data / backup dirs and set ownership
RUN mkdir -p /app/data_volume /app/backups && \
    chown -R vigil:vigil /app

# Environment defaults
ENV HOME=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/ssl_domain_checker
ENV PORT=5000
ENV DB_PATH=/app/data_volume/ssl_checker.db
ENV BACKUP_DIR=/app/backups
ENV MAX_BACKUPS=30

USER vigil

EXPOSE 5000

CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:5000", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "-c", "gunicorn.conf.py", "app:app"]
