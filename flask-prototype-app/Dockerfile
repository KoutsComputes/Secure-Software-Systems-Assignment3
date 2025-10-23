FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

# Gurveen - Issue #2: Ensure OpenSSL is available for auto TLS certificate generation.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_DEBUG=1 \
    FLASK_APP=app.app:app

RUN chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]

# Gurveen - Issue #2: Start via python -m to leverage built-in TLS context handling.
CMD ["python", "-m", "app.app"]
