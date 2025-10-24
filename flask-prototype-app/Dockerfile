FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

# Gurveen - Issue #2: Ensure OpenSSL is available for auto TLS certificate generation.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl bash \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# Theo: Copy entrypoint outside bind-mounted /app to avoid CRLF override on Windows
COPY docker-entrypoint.sh /usr/local/bin/entry.sh
RUN sed -i 's/\r$//' /usr/local/bin/entry.sh && chmod +x /usr/local/bin/entry.sh

ENV FLASK_DEBUG=1 \
    FLASK_APP=app.app:app

# Also normalize the copy under /app for non-mounted builds
RUN sed -i 's/\r$//' /app/docker-entrypoint.sh && chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/bin/bash", "/usr/local/bin/entry.sh"]

# Gurveen - Issue #2: Start via python -m to leverage built-in TLS context handling.
CMD ["python", "-m", "app.app"]
