#!/bin/sh
# Requirement 1: auto-provision a stable AES ballot key whenever the container boots.
set -e

# Allow overrides via BALLOT_KEY_FILE; default to repo root so host volume persists it.
KEY_FILE="${BALLOT_KEY_FILE:-/app/.ballot_encryption_key}"

if [ -z "${BALLOT_ENCRYPTION_KEY:-}" ]; then
    if [ -f "$KEY_FILE" ]; then
        export BALLOT_ENCRYPTION_KEY="$(cat "$KEY_FILE")"
    else
        export BALLOT_ENCRYPTION_KEY="$(python3 - <<'PY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode('ascii'))
PY
)"
        printf "%s" "$BALLOT_ENCRYPTION_KEY" > "$KEY_FILE"
        chmod 600 "$KEY_FILE" || true
    fi
fi

# Requirement 1: surface diagnostics in Docker builds unless operator opts out.
if [ -z "${ENABLE_ENCRYPTION_DIAGNOSTICS:-}" ]; then
    export ENABLE_ENCRYPTION_DIAGNOSTICS=1
fi

# Gurveen - Issue #2: auto-provision self-signed cert for HTTPS when running in Docker.
TLS_CERT_FILE_PATH="${TLS_CERT_FILE:-/app/certs/server.crt}"
TLS_KEY_FILE_PATH="${TLS_KEY_FILE:-/app/certs/server.key}"

# Gurveen - Issue #2: Default to enabling TLS inside Docker unless explicitly disabled.
if [ -z "${TLS_ENABLE:-}" ]; then
    export TLS_ENABLE=true
else
    export TLS_ENABLE="${TLS_ENABLE}"
fi

export TLS_CERT_FILE="${TLS_CERT_FILE_PATH}"
export TLS_KEY_FILE="${TLS_KEY_FILE_PATH}"

if [ "${TLS_ENABLE}" = "true" ] || [ "${TLS_ENABLE}" = "1" ]; then
    CERT_DIR="$(dirname "${TLS_CERT_FILE_PATH}")"
    mkdir -p "${CERT_DIR}"
    if [ ! -f "${TLS_CERT_FILE_PATH}" ] || [ ! -f "${TLS_KEY_FILE_PATH}" ]; then
        # Gurveen - Issue #2: Generate a fresh self-signed certificate using OpenSSL (available in image).
        openssl req -x509 -newkey rsa:2048 \
            -keyout "${TLS_KEY_FILE_PATH}" \
            -out "${TLS_CERT_FILE_PATH}" \
            -days 365 \
            -nodes \
            -subj "/CN=localhost" >/tmp/openssl.log 2>&1 || {
                echo "Failed to auto-generate TLS certificate. See /tmp/openssl.log for details." >&2
                cat /tmp/openssl.log >&2 || true
                exit 1
            }
        chmod 600 "${TLS_KEY_FILE_PATH}" || true
    fi
fi

# Gurveen - Issue #3: Ensure Docker replicas share limiter counters via Redis service by default.
if [ -z "${RATE_LIMIT_STORAGE_URI:-}" ]; then
    export RATE_LIMIT_STORAGE_URI="redis://redis:6379/0"
fi

# Gurveen - Issue #3: Default per-IP ceiling keeps DDoS spray in check without extra switches.
if [ -z "${RATE_LIMIT_DEFAULT:-}" ]; then
    export RATE_LIMIT_DEFAULT="50 per minute"
fi

exec "$@"
