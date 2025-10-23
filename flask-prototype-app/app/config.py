import os

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')

# Prefer env DATABASE_URL; otherwise default to local SQLite for easy prototyping
SQLALCHEMY_DATABASE_URI = os.environ.get(
    'DATABASE_URL',
    f"sqlite:///{os.path.join(os.path.dirname(__file__), 'data.db')}"
)
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Tamper-evident audit log configuration
AUDIT_LOG_PATH = os.environ.get('AUDIT_LOG_PATH', os.path.join(os.path.dirname(__file__), 'logs', 'audit.log'))
AUDIT_LOG_KEY = os.environ.get('AUDIT_LOG_KEY', SECRET_KEY)

# Geolocation restrictions (ISO country codes, comma-separated). If empty, allow all.
# When behind Cloudflare, 'CF-IPCountry' header will be used.
ALLOWED_COUNTRIES = os.environ.get('ALLOWED_COUNTRIES', '')

# Gurveen - Issue #1: allow operators to override AES ballot key with a base64-encoded 32 byte value.
BALLOT_ENCRYPTION_KEY = os.environ.get('BALLOT_ENCRYPTION_KEY', '')

# Gurveen - Issue #1 diagnostics: optional UI that proves ballots are encrypted end-to-end.
ENABLE_ENCRYPTION_DIAGNOSTICS = os.environ.get('ENABLE_ENCRYPTION_DIAGNOSTICS', '0').lower() in {'1', 'true', 'yes'}
# Theo: Issue 6 - Harden session cookies (override via env if needed)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

# Gurveen - Issue #2: TLS configuration (development/runtime)
# Gurveen - Issue #2: Provide paths to certificate and private key to enable HTTPS using Flask's built-in SSL context.
# Gurveen - Issue #2: Use self-signed certs for local/dev; supply real certs in production via reverse proxy/terminator.
TLS_CERT_FILE = os.environ.get('TLS_CERT_FILE', '')
TLS_KEY_FILE = os.environ.get('TLS_KEY_FILE', '')
TLS_ENABLE = os.environ.get('TLS_ENABLE', 'false').lower() in {'1', 'true', 'yes'}

# Theo: Issue 6 - Feature flag to enforce MFA on /vote
ENFORCE_MFA_ON_VOTE = os.environ.get('ENFORCE_MFA_ON_VOTE', 'false').lower() == 'true'

# Gurveen - Issue #1: default admin bootstrap so UI login works without CLI seeding
# Default accounts are fixed for controlled testing; overrides via env are intentionally ignored.
DEFAULT_ADMIN_USERNAME = 'admin'
DEFAULT_ADMIN_PASSWORD = 'SecureAdm#12'

DEFAULT_CLERK_USERNAME = 'clerk'
DEFAULT_CLERK_PASSWORD = 'Clerk#12AB34'

DEFAULT_VOTER_USERNAME = 'voter'
DEFAULT_VOTER_PASSWORD = 'Voter#56CD78'

# Gurveen - Issue #3: Default rate limiting policy - restrict abusive clients while keeping voters flowing.
RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '50 per minute')
# Gurveen - Issue #3: Central store for rate limiting counters; use Redis for cross-container consistency.
RATE_LIMIT_STORAGE_URI = os.environ.get('RATE_LIMIT_STORAGE_URI', 'memory://')
# Gurveen - Issue #3: Respect trusted proxy headers (comma separated) to pull the real client IP.
RATE_LIMIT_TRUSTED_IP_HEADERS = [
    header.strip() for header in os.environ.get(
        'RATE_LIMIT_TRUSTED_IP_HEADERS',
        'CF-Connecting-IP,X-Forwarded-For'
    ).split(',')
    if header.strip()
]
