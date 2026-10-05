FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

WORKDIR /app

# Dependencies at the pinned versions. Every one ships a wheel for this image,
# so no compiler is installed.
COPY requirements.lock .
RUN pip install -r requirements.lock

COPY . .

# Run unprivileged. /data holds what the server writes: uploaded captures, the
# baseline and plan stores, and the audit log. Mount a volume there to keep it.
RUN useradd --system --create-home --uid 10001 cipherguard \
    && mkdir -p /data/captures \
    && cp samples/*.pcap /data/captures/ \
    && chown -R cipherguard:cipherguard /data
USER cipherguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT', '8000'), timeout=4)"

# A container has to bind 0.0.0.0 to be reachable through a published port,
# and the server refuses that bind without a token, so the container will not
# start unauthenticated:
#   docker run -e CIPHERGUARD_TOKEN=$(openssl rand -hex 32) -p 8000:8000 <image>
CMD ["python", "-m", "cipherguard.cli", "serve", "--host", "0.0.0.0", \
     "--captures", "/data/captures", "--db", "/data/baseline.db", \
     "--audit-log", "/data/audit.jsonl"]
