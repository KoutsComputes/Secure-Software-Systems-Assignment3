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

exec "$@"
