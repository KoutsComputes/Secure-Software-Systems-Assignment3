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
