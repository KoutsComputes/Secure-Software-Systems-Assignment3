import hashlib
import hmac
import json
import os
import threading
import time
from typing import Optional

from flask import current_app, request


class TamperEvidentLogger:
    """
    Simple append-only, tamper-evident logger using an HMAC-SHA256 hash chain.
    Each record contains: ts, actor, action, details, ip, prev_hash, mac.
    """

    _lock = threading.Lock()

    def __init__(self, log_path: str, key: str):
        self.log_path = log_path
        self.key = key.encode('utf-8') if isinstance(key, str) else key
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

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
            payload = {
                'ts': ts,
                'actor': actor or 'system',
                'action': action,
                'details': details or {},
                'ip': ip,
                'prev_mac': prev_mac,
            }
            mac = hmac.new(self.key, json.dumps(payload, sort_keys=True).encode('utf-8'), hashlib.sha256).hexdigest()
            payload['mac'] = mac
            with open(self.log_path, 'ab') as f:
                f.write((json.dumps(payload, sort_keys=True) + "\n").encode('utf-8'))
            return mac

    def verify(self) -> bool:
        try:
            prev = ''
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
                    payload = {k: rec[k] for k in rec if k != 'mac'}
                    mac_calc = hmac.new(self.key, json.dumps(payload, sort_keys=True).encode('utf-8'), hashlib.sha256).hexdigest()
                    if mac_calc != rec.get('mac'):
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


def is_country_allowed() -> bool:
    allowed = current_app.config.get('ALLOWED_COUNTRIES', '')
    if not allowed:
        return True  # no restriction configured
    allowed_set = {c.strip().upper() for c in allowed.split(',') if c.strip()}
    country = request.headers.get('CF-IPCountry')
    if not country:
        # If not behind Cloudflare, allow unless explicitly configured to block unknown.
        # Conservatively deny when policy is set and country unknown.
        return False
    return country.upper() in allowed_set
