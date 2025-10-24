"""
Backwards compat shim so legacy imports (`from app import routes`) keep working.
All route registrations now live in `app.app`.
"""

from .app import app, db  # re-export the configured application objects

__all__ = ["app", "db"]
