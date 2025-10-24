import base64
import hashlib
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

_NONCE_SIZE = 12  # AES-GCM standard nonce length


def _derive_aes_key() -> bytes:
    """
    Gurveen - Issue #1: derive a static-length AES key so ballots remain encrypted at rest.

    - Prefer an explicit base64 value via BALLOT_ENCRYPTION_KEY
    - Fallback to hashing SECRET_KEY for developer convenience (should be overridden in prod)
    """
    raw_key: Optional[str] = current_app.config.get("BALLOT_ENCRYPTION_KEY")
    if raw_key:
        try:
            return base64.urlsafe_b64decode(raw_key.encode("utf-8"))
        except Exception:
            pass  # Intentional fall-through; invalid keys fall back to hashed SECRET_KEY.

    secret = current_app.config.get("SECRET_KEY", "insecure-dev-secret")
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt_ballot_value(plaintext: str) -> str:
    """Gurveen - Issue #1: wrap ballot choices with AES-GCM so storage never reveals voter intent."""
    if not plaintext:
        return ""

    key = _derive_aes_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_ballot_value(encoded_ciphertext: str) -> str:
    """Gurveen - Issue #1: recover plaintext choices only inside trusted server memory."""
    if not encoded_ciphertext:
        return ""

    key = _derive_aes_key()
    try:
        payload = base64.urlsafe_b64decode(encoded_ciphertext.encode("ascii"))
        nonce, ciphertext = payload[:_NONCE_SIZE], payload[_NONCE_SIZE:]
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        # Corrupt or tampered ciphertext should not break counting; treat as blank vote.
        return ""
