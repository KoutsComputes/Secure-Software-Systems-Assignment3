from .app import (
    db,
    Voter,
    Candidate,
    Vote,
    VoteReceipt,
    UserAccount,
    Role,
)

# Maintain the legacy name expected by older blueprints/views.
User = UserAccount

__all__ = [
    "db",
    "Voter",
    "Candidate",
    "Vote",
    "VoteReceipt",
    "UserAccount",
    "Role",
    "User",
]
