import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
from typing import Optional, Tuple

from flask import current_app, request
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class DigitalSignatureManager:
    """Gurveen - Issue #4: coordinate per-actor Ed25519 key material so every audit trail entry carries a provable signer."""

    _lock = threading.Lock()
    _safe_actor_pattern = re.compile(r'[^a-zA-Z0-9_.-]+')

    def __init__(self, key_dir: str, auto_provision: bool = True):
        self.key_dir = key_dir
        self.auto_provision = bool(auto_provision)
        os.makedirs(self.key_dir, exist_ok=True)

    def _safe_actor(self, actor: Optional[str]) -> str:
        canon = actor or 'system'
        return self._safe_actor_pattern.sub('_', canon)

    def _key_paths(self, actor: str) -> Tuple[str, str]:
        safe_actor = self._safe_actor(actor)
        return (
            os.path.join(self.key_dir, f"{safe_actor}.priv"),
            os.path.join(self.key_dir, f"{safe_actor}.pub"),
        )

    def _ensure_keys(self, actor: str) -> None:
        # Gurveen - Issue #4: lazily materialise signing keys the first time an actor is seen, ensuring non-repudiation
        # still works for accounts created at runtime without requiring a maintenance window.
        priv_path, pub_path = self._key_paths(actor)
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            return
        if not self.auto_provision:
            raise RuntimeError(f"Digital signature key missing for actor '{actor}' and auto-provisioning disabled.")
        with self._lock:
            if os.path.exists(priv_path) and os.path.exists(pub_path):
                return
            key = Ed25519PrivateKey.generate()
            priv_bytes = key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_bytes = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            with open(priv_path, 'wb') as priv_file:
                priv_file.write(priv_bytes)
            with open(pub_path, 'wb') as pub_file:
                pub_file.write(pub_bytes)
            try:
                os.chmod(priv_path, 0o600)
            except (PermissionError, NotImplementedError):
                pass  # Gurveen - Issue #4: chmod best-effort on non-POSIX filesystems.

    def _load_private_key(self, actor: str) -> Ed25519PrivateKey:
        self._ensure_keys(actor)
        priv_path, _ = self._key_paths(actor)
        with open(priv_path, 'rb') as priv_file:
            priv_bytes = priv_file.read()
        return Ed25519PrivateKey.from_private_bytes(priv_bytes)

    # Expose private/public key objects for JWT signing when EdDSA is required.
    def get_private_key(self, actor: str) -> Ed25519PrivateKey:
        return self._load_private_key(actor)

    def get_public_key_b64(self, actor: str) -> str:
        # Gurveen - Issue #4: expose public keys in base64 so auditors can export them into separate tooling for signature validation.
        self._ensure_keys(actor)
        _, pub_path = self._key_paths(actor)
        with open(pub_path, 'rb') as pub_file:
            pub_bytes = pub_file.read()
        return base64.b64encode(pub_bytes).decode('ascii')

    def sign_payload(self, actor: str, payload: bytes) -> str:
        """Gurveen - Issue #4: sign canonical log payload and surface signature as base64 for storage alongside the log."""
        private_key = self._load_private_key(actor)
        signature = private_key.sign(payload)
        return base64.b64encode(signature).decode('ascii')

    def verify_signature(self, public_key_b64: str, payload: bytes, signature_b64: str) -> bool:
        # Gurveen - Issue #4: allow offline proof that an audit entry was signed by the claimed actor and has not been re-written.
        try:
            public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, payload)
            return True
        except (ValueError, InvalidSignature):
            return False


class TamperEvidentLogger:
    """
    Gurveen - Issue #4: enhance the append-only HMAC chain with Ed25519 digital signatures so repudiation attempts fail.
    Each record contains: ts, actor, action, details, ip, prev_hash, mac, signature metadata.
    """

    _lock = threading.Lock()

    def __init__(self, log_path: str, key: str):
        self.log_path = log_path
        self.key = key.encode('utf-8') if isinstance(key, str) else key
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self._upgrade_legacy_signatures()

    def _upgrade_legacy_signatures(self) -> None:
        if not os.path.exists(self.log_path):
            return
        try:
            with self._lock:
                try:
                    with open(self.log_path, 'rb') as handle:
                        raw_lines = handle.readlines()
                except FileNotFoundError:
                    return
                signature_manager = get_signature_manager()
                updated_lines = []
                changed = False
                for raw in raw_lines:
                    try:
                        decoded = raw.decode('utf-8')
                    except UnicodeDecodeError:
                        updated_lines.append(raw)
                        continue
                    stripped = decoded.strip()
                    if not stripped:
                        updated_lines.append(raw)
                        continue
                    try:
                        record = json.loads(stripped)
                    except json.JSONDecodeError:
                        updated_lines.append(raw)
                        continue
                    if record.get('signature_alg') == 'ed25519' and record.get('signature') and record.get('signing_public_key'):
                        updated_lines.append((json.dumps(record, sort_keys=True) + "\n").encode('utf-8'))
                        continue
                    base_payload = {
                        key: record[key]
                        for key in record
                        if key not in {'signature', 'signing_public_key', 'signature_alg'}
                    }
                    actor = record.get('actor', 'system')
                    sign_body = json.dumps(base_payload, sort_keys=True).encode('utf-8')
                    try:
                        signature = signature_manager.sign_payload(actor, sign_body)
                        record['signature'] = signature
                        record['signing_public_key'] = signature_manager.get_public_key_b64(actor)
                        record['signature_alg'] = 'ed25519'
                        changed = True
                        updated_lines.append((json.dumps(record, sort_keys=True) + "\n").encode('utf-8'))
                    except Exception:
                        updated_lines.append(raw)
                if changed:
                    with open(self.log_path, 'wb') as handle:
                        handle.writelines(updated_lines)
        except Exception:
            # On any failure, leave the log untouched; verification will surface issues to admins.
            return

    def _last_hash(self) -> str:
        try:
            with open(self.log_path, 'rb') as f:
                last = b''
                for line in f:
                    if line.strip():  # skip blanks
                        last = line
                if not last:
                    return ''
                rec = json.loads(last.decode('utf-8'))
                return rec.get('mac', '')
        except (FileNotFoundError, json.JSONDecodeError):
            # Treat missing or malformed tail as no prior hash
            return ''

    def log(self, action: str, actor: Optional[str] = None, details: Optional[dict] = None):
        with self._lock:
            ts = int(time.time())
            ip = None
            try:
                ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            except Exception:
                ip = None
            prev_mac = self._last_hash()
            payload_base = {
                'ts': ts,
                'actor': actor or 'system',
                'action': action,
                'details': details or {},
                'ip': ip,
                'prev_mac': prev_mac,
            }
            canonical = json.dumps(payload_base, sort_keys=True).encode('utf-8')
            mac = hmac.new(self.key, canonical, hashlib.sha256).hexdigest()
            record = dict(payload_base)
            record['mac'] = mac
            # Gurveen - Issue #4: append Ed25519 signature so auditors can attribute actions definitively.
            signature_manager = get_signature_manager()  # Gurveen - Issue #4: reuse the shared signing service to avoid diverging key stores.
            sign_body = json.dumps(record, sort_keys=True).encode('utf-8')
            signature = signature_manager.sign_payload(record['actor'], sign_body)
            record['signature'] = signature
            record['signing_public_key'] = signature_manager.get_public_key_b64(record['actor'])
            record['signature_alg'] = 'ed25519'
            with open(self.log_path, 'ab') as f:
                f.write((json.dumps(record, sort_keys=True) + "\n").encode('utf-8'))
            return mac

    def verify(self) -> bool:
        try:
            prev = ''
            signature_manager = get_signature_manager()  # Gurveen - Issue #4: use the same manager during verification to pull stored public keys reliably.
            with open(self.log_path, 'rb') as f:
                for raw in f:
                    line = raw.decode('utf-8').strip()
                    if not line:
                        continue  # ignore blank lines
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        return False
                    if rec.get('prev_mac', '') != prev:
                        return False
                    payload_for_mac = {
                        k: rec[k] for k in rec
                        if k not in {'mac', 'signature', 'signing_public_key', 'signature_alg'}
                    }
                    mac_calc = hmac.new(self.key, json.dumps(payload_for_mac, sort_keys=True).encode('utf-8'), hashlib.sha256).hexdigest()
                    if mac_calc != rec.get('mac'):
                        return False
                    signature = rec.get('signature')
                    public_key_b64 = rec.get('signing_public_key')
                    algorithm = rec.get('signature_alg', '')
                    if algorithm != 'ed25519' or not signature or not public_key_b64:
                        return False
                    # Gurveen - Issue #4: re-create the original signing document and validate the Ed25519 signature so attackers cannot swap payloads without detection.
                    sign_body = json.dumps(
                        {k: rec[k] for k in rec if k not in {'signature', 'signing_public_key', 'signature_alg'}},
                        sort_keys=True
                    ).encode('utf-8')
                    if not signature_manager.verify_signature(public_key_b64, sign_body, signature):
                        return False
                    prev = rec.get('mac', '')
            return True
        except FileNotFoundError:
            return True
        except Exception:
            # Any unexpected error => treat as verification failure (tampered)
            return False


def get_audit_logger() -> TamperEvidentLogger:
    cfg = current_app.config
    return TamperEvidentLogger(cfg['AUDIT_LOG_PATH'], cfg['AUDIT_LOG_KEY'])


def get_signature_manager() -> DigitalSignatureManager:
    cfg = current_app.config
    # Gurveen - Issue #4: centralise access to the signing manager so every module reuses the same key directory and policy.
    return DigitalSignatureManager(cfg['DIGITAL_SIGNATURE_KEY_DIR'], cfg.get('DIGITAL_SIGNATURE_AUTO_PROVISION', True))


def is_country_allowed() -> bool:
    allowed = current_app.config.get('ALLOWED_COUNTRIES', '')
    if not allowed:
        return True  # no restriction configured
    allowed_set = {c.strip().upper() for c in allowed.split(',') if c.strip()}
    country = request.headers.get('CF-IPCountry')
    if not country:
        # Try local GeoIP lookup when configured
        db_path = current_app.config.get('GEOIP_DB_PATH', '')
        if db_path and os.path.exists(db_path):
            try:
                from geoip2.database import Reader  # type: ignore
                with Reader(db_path) as reader:
                    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
                    ip = (ip or '').split(',')[0].strip()
                    if ip:
                        resp = reader.country(ip)
                        country = (resp.country.iso_code or '').upper()
            except Exception:
                country = None
        if not country:
            # Conservatively deny when policy is set and country unknown.
            return False
    return country.upper() in allowed_set
