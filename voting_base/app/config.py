import os

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')

# Prefer env DATABASE_URL; otherwise default to local SQLite for easy prototyping
SQLALCHEMY_DATABASE_URI = os.environ.get(
    'DATABASE_URL',
    f"sqlite:///{os.path.join(os.path.dirname(__file__), 'data.db')}"
)
SQLALCHEMY_TRACK_MODIFICATIONS = False
