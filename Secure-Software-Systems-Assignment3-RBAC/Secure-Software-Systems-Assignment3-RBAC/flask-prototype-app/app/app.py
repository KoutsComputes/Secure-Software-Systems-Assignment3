from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session  # Theo: Issue 6 - session for auth
import json  # Gurveen - Issue #4: parse audit log entries for signature diagnostics.
import os
import uuid
import hmac
import hashlib
import time
from datetime import datetime, timedelta  # Gurveen - Issue #4: present audit timestamps in the signature tester UI. Gurveen - Issue #2: TLS cert validity window.
import re
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text  # Theo: lightweight schema migrations without Alembic
from werkzeug.security import generate_password_hash, check_password_hash  # Theo: Issue 6 - password hashing
import pyotp  # Theo: Issue 6 - TOTP MFA
import qrcode  # Theo: Issue 6 - QR code generation for TOTP setup
import base64  # Theo: Issue 6 - Encode QR image for template
from io import BytesIO  # Theo: Issue 6 - In-memory image buffer
from flask_limiter import Limiter  # Gurveen - Issue #3: in-app rate limiting
from flask_limiter.util import get_remote_address  # Gurveen - Issue #3: helper fallback
from limits import parse as parse_rate_limit  # Gurveen - Issue #3: parse human-friendly policies
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
# Support running as a script or as a package
try:
    from security import get_audit_logger, get_signature_manager, is_country_allowed  # when running app/app.py directly
    from crypto_utils import encrypt_ballot_value, decrypt_ballot_value
except ImportError:
    from .security import get_audit_logger, get_signature_manager, is_country_allowed  # when imported as package
    from .crypto_utils import encrypt_ballot_value, decrypt_ballot_value  # Gurveen - Issue #1: AES ballot helpers

app = Flask(__name__)
# Avoid import-time package/module name conflicts by loading config from file path
_basedir = os.path.dirname(__file__)
app.config.from_pyfile(os.path.join(_basedir, 'config.py'))
db = SQLAlchemy(app)

# Simple in-memory cache for frequently accessed data (Requirement 14)
_cache_store = {}

def _cache_get(name: str):
    entry = _cache_store.get(name)
    if not entry:
        return None, False
    value, expires_at = entry
    if expires_at < time.time():
        _cache_store.pop(name, None)
        return None, False
    return value, True

def _cache_set(name: str, value, ttl: int):
    _cache_store[name] = (value, time.time() + int(ttl))

def _cache_invalidate(prefix: str):
    for k in list(_cache_store.keys()):
        if k.startswith(prefix):
            _cache_store.pop(k, None)

# Gurveen - Issue #4: guarantee every actor has a dedicated Ed25519 signing identity on disk so their future actions can
# be signed without delays and auditors can verify which credential authored any given audit trail event.
def _ensure_actor_signing_identity(actor: str) -> None:
    if not actor:
        return
    try:
        get_signature_manager().get_public_key_b64(actor)
    except Exception as exc:
        app.logger.warning("Failed to provision signing identity for %s: %s", actor, exc)

# Gurveen - Issue #3: Determine the real client IP even when behind trusted proxies/CDN.
def _resolve_client_ip():
    forwarded_headers = app.config.get('RATE_LIMIT_TRUSTED_IP_HEADERS') or []
    for header in forwarded_headers:
        value = request.headers.get(header)
        if value:
            candidate = value.split(',')[0].strip()
            if candidate:
                return candidate
    # Fall back to Werkzeug's remote address helper when no proxy headers are present.
    return get_remote_address()

# Gurveen - Issue #3: Enforce a per-IP rate ceiling across all containers using shared storage.
limiter = Limiter(
    key_func=_resolve_client_ip,
    app=app,
    default_limits=[app.config.get('RATE_LIMIT_DEFAULT')],
    storage_uri=app.config.get('RATE_LIMIT_STORAGE_URI'),
    strategy='fixed-window-elastic-expiry',  # Gurveen - Issue #3: steady fairness under bursts.
    headers_enabled=True
)

# Requirement 16/20: basic input validators/sanitizers
_re_csv_numbers = re.compile(r"[^0-9,]+")
_re_csv_words = re.compile(r"[^A-Za-z0-9 \-']+")

def _sanitize_csv_numbers(raw: str) -> str:
    cleaned = _re_csv_numbers.sub('', raw or '')
    parts = [p.strip() for p in cleaned.split(',') if p.strip().isdigit()]
    return ','.join(parts)

def _sanitize_csv_words(raw: str) -> str:
    cleaned = _re_csv_words.sub('', raw or '')
    parts = [p.strip() for p in cleaned.split(',') if p.strip()]
    return ','.join(parts)

# Gurveen - Issue #2: Generate self-signed TLS certificates on-demand for localhost testing.
def _ensure_self_signed_certificates(cert_path: str, key_path: str) -> None:
    if not cert_path or not key_path:
        return
    cert_exists = os.path.exists(cert_path)
    key_exists = os.path.exists(key_path)
    if cert_exists and key_exists:
        return
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "VIC"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Melbourne"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureVote Prototype"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, 'wb') as f_key:
        f_key.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open(cert_path, 'wb') as f_cert:
        f_cert.write(cert.public_bytes(serialization.Encoding.PEM))

# Gurveen - Issue #3: Convert configured policy into a reusable RateLimitItem.
def _default_rate_limit_item():
    policy = app.config.get('RATE_LIMIT_DEFAULT') or "50 per minute"
    try:
        return parse_rate_limit(policy)
    except ValueError:
        # Gurveen - Issue #3: Fall back gracefully if operators misconfigure the limit string.
        return parse_rate_limit("50 per minute")

# Simple list of allowed mission codes for overseas voting (prototype)
ALLOWED_MISSIONS = {"AUS-LONDON", "AUS-WASHINGTON", "AUS-TOKYO", "AUS-SINGAPORE"}

def _encryption_diagnostics_enabled() -> bool:
    """Gurveen - Issue #1: guard diagnostics so plaintext exposure only happens when explicitly allowed."""
    return bool(app.config.get('ENABLE_ENCRYPTION_DIAGNOSTICS'))

@app.route('/dev/admin-login', methods=['POST'])
def dev_admin_login():
    """Simple dev helper: when diagnostics are enabled, log in as admin without MFA.
    Hidden behind the diagnostics flag to avoid exposure in production.
    """
    if not _encryption_diagnostics_enabled():
        return abort(404)
    # Ensure an admin exists (seed if missing)
    username = app.config.get('DEFAULT_ADMIN_USERNAME', 'admin')
    password = app.config.get('DEFAULT_ADMIN_PASSWORD', 'SecureAdm#12')
    user = UserAccount.query.filter_by(username=username).first()
    if not user:
        user = UserAccount(
            username=username,
            password_hash=generate_password_hash(password),
            role='admin'
        )
        db.session.add(user)
        db.session.commit()
        _ensure_actor_signing_identity(user.username)
    else:
        # Gurveen - Issue #4: reconcile pre-existing admin accounts with the signing vault so their later actions are still attributable.
        _ensure_actor_signing_identity(user.username)
    # Log in (skip MFA for diagnostics convenience)
    session['user_id'] = user.id
    session['mfa_ok'] = True
    flash('Logged in as admin (dev).')
    return redirect(url_for('home_landing'))

# Ensure tables exist when running via `flask run` (not just `python app.py`)
@app.before_first_request
def _init_db():
    db.create_all()
    # Theo: Lightweight schema migration for new columns (MySQL)
    def _lightweight_migrations():
        try:
            with db.engine.connect() as conn:
                try:
                    res = conn.execute(text("SHOW COLUMNS FROM user_account LIKE 'is_eligible'"))
                    row = res.fetchone()
                    needs_col = row is None
                except Exception:
                    needs_col = True
                if needs_col:
                    try:
                        conn.execute(text("ALTER TABLE user_account ADD COLUMN is_eligible TINYINT(1) NOT NULL DEFAULT 0"))
                    except Exception as e:
                        app.logger.warning("Theo: schema migration (is_eligible) skipped or failed: %s", e)
        except Exception as e:
            app.logger.warning("Theo: migration check failed: %s", e)

    _lightweight_migrations()
    # Theo: Issue 8 - Seed default roles (DB-level RBAC)
    try:
        existing = {r.name for r in Role.query.all()}
    except Exception:
        existing = set()
    for rname, desc in (
        ('voter', 'Regular voter with minimal privileges'),
        ('clerk', 'Polling clerk: verify enrollment, assist voters'),
        ('admin', 'System admin: manage candidates and system areas'),
    ):
        if rname not in existing:
            db.session.add(Role(name=rname, description=desc))
    db.session.commit()
    _ensure_actor_signing_identity('system')  # Gurveen - Issue #4: provision a deterministic key for automated/system actors.
    # Theo: Issue 8 - Optional admin bootstrap via env (for backend RBAC testing)
    admin_user = os.environ.get('BOOTSTRAP_ADMIN_USERNAME')
    admin_pass = os.environ.get('BOOTSTRAP_ADMIN_PASSWORD')
    if admin_user and admin_pass:
        if not UserAccount.query.filter_by(username=admin_user).first():
            db.session.add(UserAccount(
                username=admin_user,
                password_hash=generate_password_hash(admin_pass),
                role='admin'
            ))
            db.session.commit()
        # Gurveen - Issue #4: sync bootstrap accounts with the signer so admin automation has non-repudiation from the first login.
        _ensure_actor_signing_identity(admin_user)
    # Gurveen - Issue #1: ensure default admin exists for pure UI login if not bootstrapped already.
    default_accounts = [
        (app.config.get('DEFAULT_ADMIN_USERNAME'), app.config.get('DEFAULT_ADMIN_PASSWORD'), 'admin'),
        (app.config.get('DEFAULT_CLERK_USERNAME'), app.config.get('DEFAULT_CLERK_PASSWORD'), 'clerk'),
        (app.config.get('DEFAULT_VOTER_USERNAME'), app.config.get('DEFAULT_VOTER_PASSWORD'), 'voter'),
    ]
    for username, password, role in default_accounts:
        if not username or not password:
            continue
        user = UserAccount.query.filter_by(username=username).first()
        if not user:
            user = UserAccount(
                username=username,
                password_hash=generate_password_hash(password),
                role=role
            )
            db.session.add(user)
            db.session.commit()
            _ensure_actor_signing_identity(username)  # Gurveen - Issue #4: seed signing keys with default accounts to avoid unsigned admin actions.
            continue
        updates = False
        if not check_password_hash(user.password_hash, password):
            user.password_hash = generate_password_hash(password)
            updates = True
        if user.role != role:
            user.role = role
            updates = True
        if updates:
            db.session.commit()
        _ensure_actor_signing_identity(username)  # Gurveen - Issue #4: refresh key material linkage whenever account credentials change.

@app.context_processor
def _inject_feature_flags():
    return {
        'encryption_diagnostics_enabled': _encryption_diagnostics_enabled()
    }

# Gurveen - Issue #2: Enforce HTTPS (redirect) and HSTS when TLS is enabled
@app.before_request
def _force_https_when_enabled():
    try:
        if not app.config.get('TLS_ENABLE'):
            return
        if request.endpoint in {'healthz'}:
            return
        if request.is_secure:
            return
        # Gurveen - Issue #2: Respect common proxy header if behind reverse proxy
        if request.headers.get('X-Forwarded-Proto', '').lower() == 'https':
            return
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)
    except Exception:
        return

# Gurveen - Issue #2: Apply strict transport and hardening headers when TLS active
@app.after_request
def _apply_security_headers(resp):
    try:
        if app.config.get('TLS_ENABLE'):
            # Gurveen - Issue #2: 6 months HSTS, include subdomains, preload optional
            resp.headers.setdefault('Strict-Transport-Security', 'max-age=15552000; includeSubDomains')
        # Gurveen - Issue #2: Basic hardening
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        resp.headers.setdefault('X-Frame-Options', 'DENY')
        resp.headers.setdefault('Referrer-Policy', 'no-referrer')
        # Requirement 14: cache headers for common, safe GET views
        cacheable_endpoints = {'candidates', 'results', 'api_results'}
        if request.endpoint in cacheable_endpoints and request.method == 'GET':
            resp.headers.setdefault('Cache-Control', 'public, max-age=30')
    except Exception:
        # Keep response flowing even if header injection fails (logging handled upstream).
        pass
    return resp

# Models
class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    enrolled = db.Column(db.Boolean, default=False)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    party = db.Column(db.String(120), nullable=False)
    order = db.Column(db.Integer, nullable=True)  # Order within party group

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('voter.id'), nullable=False)
    house_preferences = db.Column(db.String(200), nullable=True)  # Comma-separated candidate IDs
    senate_above = db.Column(db.String(200), nullable=True)       # Comma-separated party names
    senate_below = db.Column(db.String(200), nullable=True)       # Comma-separated candidate IDs
    source = db.Column(db.String(50), default="electronic")      # 'electronic' or 'scanned'


class VoteReceipt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vote_id = db.Column(db.Integer, db.ForeignKey('vote.id'), nullable=False)
    receipt = db.Column(db.String(64), unique=True, nullable=False)


def _generate_receipt(vote_obj: 'Vote', source: str = 'electronic') -> str:
    """Requirement 10: metadata-based receipt formula (HMAC day-scoped).

    Code = YYYYMMDD-<16 hex chars>
    HMAC over: vote_id : yyyymmdd : source : CF-IPCountry (if any)
    """
    secret = app.config.get('RECEIPT_SECRET', app.config.get('SECRET_KEY', ''))
    ymd = datetime.utcnow().strftime('%Y%m%d')
    country = request.headers.get('CF-IPCountry', 'XX') or 'XX'
    msg = f"{vote_obj.id}:{ymd}:{source}:{country}"
    digest = hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{ymd}-{digest[:16].upper()}"

# Theo: Issue 6 - Authentication model (password + TOTP secret)
class UserAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    voter_id = db.Column(db.Integer, db.ForeignKey('voter.id'), nullable=True)
    # Theo: Issue 8 - RBAC in database: role persisted on the user
    role = db.Column(db.String(32), db.ForeignKey('role.name'), nullable=False, default='voter')
    # Theo: Issue 7/8 - Voter eligibility requires clerk/admin approval before voting
    is_eligible = db.Column(db.Boolean, default=False)

# Theo: Issue 8 - Roles table in database (separate DB layer for RBAC)
class Role(db.Model):
    name = db.Column(db.String(32), primary_key=True)
    description = db.Column(db.String(200))

# Routes

@app.route('/')
def index():
    # Theo: Issue 6/7 - Default UX: send users to auth first
    # If not logged in, show login; if logged in, go to role dashboard.
    user = _current_user()
    if not user:
        return redirect(url_for('auth_login'))
    return redirect(url_for('dashboard_root'))

# Theo: Issue 7 - Preserve access to the original prototype homepage
@app.route('/home')
def home_landing():
    return render_template('index.html')

# Theo: Incident Recovery - Health endpoint for Docker healthcheck
# Validates app liveness and DB connectivity so Docker can auto-restart and order services.
@limiter.exempt  # Gurveen - Issue #3: keep orchestrator health probes unrestricted.
@app.route('/healthz')
def healthz():
    try:
        db.session.execute('SELECT 1')
        return jsonify({'status': 'ok', 'db': 'ok'}), 200
    except Exception as e:  # pragma: no cover
        return jsonify({'status': 'error', 'db': 'unhealthy', 'detail': str(e)}), 500

# Theo: Issue 6 - helpers for authentication state
def _current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return UserAccount.query.get(uid)

def login_required_and_mfa(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = _current_user()
        if not user:
            flash('Please log in to continue.')
            return redirect(url_for('auth_login'))
        if user.mfa_enabled and not session.get('mfa_ok'):
            flash('Please complete MFA verification.')
            return redirect(url_for('auth_mfa_prompt'))
        return fn(*args, **kwargs)
    return wrapper

# Theo: Issue 8 - API RBAC decorator for role-based access control (no JWT)
def role_required(*roles):
    from functools import wraps
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = _current_user()
            if not user:
                flash('Please log in to continue.')
                return redirect(url_for('auth_login'))
            if user.role not in roles:
                flash('You do not have permission to access this page.')
                return abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# Theo: Issue 7 - Inject current user/role into templates for nav rendering
@app.context_processor
def _inject_user_role():
    user = _current_user()
    return {
        'current_user': user,
        'user_role': (user.role if user else None)
    }

# Theo: Issue 6/7 - Global strict auth: require login + MFA for all non-auth routes
@app.before_request
def _global_auth_mfa_enforcement():
    # Disabled for simplified demo: no login/MFA required anywhere.
    return None
    if user.mfa_enabled and not session.get('mfa_ok') and request.endpoint not in {'auth_mfa_prompt'}:
        # Enforce MFA verification for this session
        flash('Please complete MFA verification.')
        return redirect(url_for('auth_mfa_prompt'))

# Theo: Issue 6 - Optionally enforce MFA on original /vote via feature flag
@app.before_request
def _enforce_mfa_on_vote():
    try:
        enforce = app.config.get('ENFORCE_MFA_ON_VOTE', False)
    except Exception:
        enforce = False
    if not enforce:
        return
    if request.endpoint == 'vote':
        user = _current_user()
        if not user:
            flash('Please log in to continue.')
            return redirect(url_for('auth_login'))
        # Theo: Issue 6 - Strict mode: require MFA to be set up for voting
        if not user.mfa_enabled:
            flash('MFA setup required before voting.')
            return redirect(url_for('auth_mfa_setup'))
        if user.mfa_enabled and not session.get('mfa_ok'):
            flash('Please complete MFA verification.')
            return redirect(url_for('auth_mfa_prompt'))

# Theo: Issue 6 - Registration (prototype)
@app.route('/auth/register', methods=['GET', 'POST'])
def auth_register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password or len(password) < 12:
            flash('Username required and password must be at least 12 characters.')
            return redirect(url_for('auth_register'))
        if UserAccount.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('auth_register'))
        # Theo: Issue 7/8 - default role is 'voter' (DB RBAC); can be elevated by admin later
        user = UserAccount(
            username=username,
            password_hash=generate_password_hash(password),
            role='voter'
        )
        db.session.add(user)
        db.session.commit()
        _ensure_actor_signing_identity(user.username)  # Gurveen - Issue #4: issue voter-specific signing keys at registration for immediate audit coverage.
        flash('Account created. Please log in and set up MFA.')
        return redirect(url_for('auth_login'))
    return render_template('auth_register.html')

# Theo: Issue 6 - Login (password step)
@app.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = UserAccount.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password.')
            return redirect(url_for('auth_login'))
        session['user_id'] = user.id
        # Theo: Admins bypass MFA setup/prompt and go straight to dashboard
        if getattr(user, 'role', None) == 'admin':
            session['mfa_ok'] = True
            flash('Logged in as admin.')
            return redirect(url_for('index'))
        # If user has MFA enabled, go to MFA prompt; otherwise mark OK
        if user.mfa_enabled:
            session['mfa_ok'] = False
            return redirect(url_for('auth_mfa_prompt'))
        session['mfa_ok'] = True
        flash('Logged in.')
        return redirect(url_for('index'))
    return render_template('auth_login.html')

# Theo: Issue 6 - MFA setup (generate TOTP secret and show otpauth URI)
@app.route('/auth/mfa-setup', methods=['GET'])
def auth_mfa_setup():
    user = _current_user()
    if not user:
        return redirect(url_for('auth_login'))
    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
        db.session.commit()
    totp = pyotp.TOTP(user.mfa_secret)
    issuer = 'SecureVotingApp'
    otpauth_uri = totp.provisioning_uri(name=user.username, issuer_name=issuer)
    # Theo: Issue 6 - Generate QR code PNG as data URI for easy scanning
    try:
        img = qrcode.make(otpauth_uri)
        buf = BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    except Exception:
        qr_b64 = None  # fallback: just show URI/secret
    return render_template('auth_mfa_setup.html', secret=user.mfa_secret, otpauth_uri=otpauth_uri, issuer=issuer, qr_b64=qr_b64)

# Theo: Issue 6 - MFA verify (enable TOTP after first successful code)
@app.route('/auth/mfa-verify', methods=['POST'])
def auth_mfa_verify():
    user = _current_user()
    if not user:
        return redirect(url_for('auth_login'))
    code = request.form.get('code', '').strip()
    if not user.mfa_secret:
        flash('No MFA secret set. Visit setup first.')
        return redirect(url_for('auth_mfa_setup'))
    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(code, valid_window=1):
        user.mfa_enabled = True
        db.session.commit()
        session['mfa_ok'] = True
        flash('MFA enabled and verified.')
        return redirect(url_for('index'))
    else:
        flash('Invalid code. Try again.')
        return redirect(url_for('auth_mfa_setup'))

# Theo: Issue 6 - MFA prompt during login
@app.route('/auth/mfa', methods=['GET', 'POST'])
def auth_mfa_prompt():
    user = _current_user()
    if not user:
        return redirect(url_for('auth_login'))
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        totp = pyotp.TOTP(user.mfa_secret or '')
        if user.mfa_enabled and totp.verify(code, valid_window=1):
            session['mfa_ok'] = True
            flash('MFA verified. You are logged in.')
            return redirect(url_for('index'))
        flash('Invalid code.')
    return render_template('auth_mfa_prompt.html')

# Theo: Issue 6 - Logout
@app.route('/auth/logout')
def auth_logout():
    session.clear()
    flash('Logged out.')
    return redirect(url_for('index'))

# Theo: Issue 6 - Protected voting route that enforces password + MFA
@app.route('/secure/vote', methods=['GET', 'POST'])
@login_required_and_mfa
def secure_vote():
    # Theo: Issue 7 - Only eligible voters can vote; others see guidance
    user = _current_user()
    if not user or user.role != 'voter':
        flash('Only voter accounts can cast votes.')
        return redirect(url_for('dashboard_root'))
    if not user.is_eligible:
        flash('Your eligibility must be verified by a clerk before voting.')
        return redirect(url_for('dashboard_voter'))
    # Reuse the existing vote handler under auth protection
    return vote()

# Theo: Issue 7 - Frontend RBAC: role-specific dashboards (no JWT)
@app.route('/dashboard')
def dashboard_root():
    user = _current_user()
    if not user:
        return redirect(url_for('auth_login'))
    if user.role == 'admin':
        return redirect(url_for('dashboard_admin'))
    if user.role == 'clerk':
        return redirect(url_for('dashboard_clerk'))
    return redirect(url_for('dashboard_voter'))

@app.route('/dashboard/voter')
@role_required('voter', 'clerk', 'admin')  # voters and higher
def dashboard_voter():
    return render_template('dashboard_voter.html')

@app.route('/dashboard/clerk')
@role_required('clerk', 'admin')
def dashboard_clerk():
    return render_template('dashboard_clerk.html')

@app.route('/dashboard/admin')
@role_required('admin')
def dashboard_admin():
    return render_template('dashboard_admin.html')

# Theo: Issue 7 - Clerk approvals: verify or deny voter eligibility
@app.route('/clerk/approvals', methods=['GET', 'POST'])
@role_required('clerk', 'admin')
def clerk_approvals():
    if request.method == 'POST':
        action = request.form.get('action', '')
        username = request.form.get('username', '').strip()
        u = UserAccount.query.filter_by(username=username).first()
        if not u:
            flash('User not found.')
            return redirect(url_for('clerk_approvals'))
        if action == 'approve':
            u.is_eligible = True
            if not u.voter_id:
                v = Voter(name=username, address='N/A', enrolled=True)
                db.session.add(v)
                db.session.commit()
                u.voter_id = v.id
            else:
                v = Voter.query.get(u.voter_id)
                if v:
                    v.enrolled = True
            db.session.commit()
            flash('Voter approved and enrolled.')
        elif action == 'deny':
            protected = {
                app.config.get('DEFAULT_ADMIN_USERNAME'),
                app.config.get('DEFAULT_CLERK_USERNAME'),
                app.config.get('DEFAULT_VOTER_USERNAME'),
            }
            if u.username in protected:
                flash('Cannot delete protected default accounts.')
                return redirect(url_for('clerk_approvals'))
            if u.voter_id and Vote.query.filter_by(voter_id=u.voter_id).first():
                flash('Cannot delete account with recorded votes.')
                return redirect(url_for('clerk_approvals'))
            if u.voter_id:
                v = Voter.query.get(u.voter_id)
                if v:
                    db.session.delete(v)
            db.session.delete(u)
            db.session.commit()
            flash('Voter denied and account removed.')
        return redirect(url_for('clerk_approvals'))
    pending = UserAccount.query.filter_by(role='voter', is_eligible=False).order_by(UserAccount.username).all()
    return render_template('clerk_approvals.html', pending=pending)

# Theo: Issue 8 - Admin: manage users (create/delete/role)
@app.route('/admin/accounts', methods=['GET', 'POST'])
@role_required('admin')
def admin_accounts():
    protected = {
        app.config.get('DEFAULT_ADMIN_USERNAME'),
        app.config.get('DEFAULT_CLERK_USERNAME'),
        app.config.get('DEFAULT_VOTER_USERNAME'),
    }
    if request.method == 'POST':
        action = request.form.get('action', 'update')
        if action == 'create':
            new_user = request.form.get('new_username', '').strip()
            new_pass = request.form.get('new_password', '').strip()
            new_role = request.form.get('new_role', 'voter').strip()
            if not new_user or not new_pass or len(new_pass) < 12:
                flash('Provide username and 12+ char password.')
                return redirect(url_for('admin_accounts'))
            if UserAccount.query.filter_by(username=new_user).first():
                flash('User already exists.')
                return redirect(url_for('admin_accounts'))
            if not Role.query.get(new_role):
                flash('Invalid role.')
                return redirect(url_for('admin_accounts'))
            u = UserAccount(username=new_user, password_hash=generate_password_hash(new_pass), role=new_role)
            db.session.add(u)
            db.session.commit()
            flash('User created.')
            return redirect(url_for('admin_accounts'))
        elif action == 'delete':
            username = request.form.get('username', '').strip()
            u = UserAccount.query.filter_by(username=username).first()
            if not u:
                flash('User not found.')
                return redirect(url_for('admin_accounts'))
            if username in protected or u.id == session.get('user_id'):
                flash('Cannot delete protected or current account.')
                return redirect(url_for('admin_accounts'))
            if u.voter_id and Vote.query.filter_by(voter_id=u.voter_id).first():
                flash('Cannot delete account with recorded votes.')
                return redirect(url_for('admin_accounts'))
            if u.voter_id:
                v = Voter.query.get(u.voter_id)
                if v:
                    db.session.delete(v)
            db.session.delete(u)
            db.session.commit()
            flash('User deleted.')
            return redirect(url_for('admin_accounts'))
        else:
            username = request.form.get('username', '').strip()
            new_role = request.form.get('role', '').strip()
            u = UserAccount.query.filter_by(username=username).first()
            if not u:
                flash('User not found.')
                return redirect(url_for('admin_accounts'))
            if not Role.query.get(new_role):
                flash('Invalid role.')
                return redirect(url_for('admin_accounts'))
            u.role = new_role
            db.session.commit()
            flash('Role updated.')
            return redirect(url_for('admin_accounts'))
    users = UserAccount.query.order_by(UserAccount.username).all()
    roles = Role.query.order_by(Role.name).all()
    return render_template('admin_accounts.html', users=users, roles=roles)

# Theo: Issue 8 - Admin: manage user roles (API + UI)
@app.route('/admin/users', methods=['GET', 'POST'])
@role_required('admin')
def admin_users():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        new_role = request.form.get('role', '').strip()
        u = UserAccount.query.filter_by(username=username).first()
        if not u:
            flash('User not found.')
            return redirect(url_for('admin_users'))
        if not Role.query.get(new_role):
            flash('Invalid role.')
            return redirect(url_for('admin_users'))
        u.role = new_role
        db.session.commit()
        flash('Role updated.')
        return redirect(url_for('admin_users'))
    users = UserAccount.query.order_by(UserAccount.username).all()
    roles = Role.query.order_by(Role.name).all()
    # Theo: Render styled template so UI matches site CSS
    return render_template('admin_users.html', users=users, roles=roles)

# Voter Registration & Enrolment
@app.route('/register_voter', methods=['GET', 'POST'])
def register_voter():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        voter = Voter(name=name, address=address, enrolled=True)
        db.session.add(voter)
        db.session.commit()
        get_audit_logger().log(
            action='register_voter',
            actor=name,
            details={'address': address}
        )
        flash('Voter registered and enrolled!')
        return redirect(url_for('index'))
    return render_template('register_voter.html')

@app.route('/check_enrolment', methods=['GET', 'POST'])
def check_enrolment():
    status = None
    if request.method == 'POST':
        name = request.form['name']
        voter = Voter.query.filter_by(name=name).first()
        if voter:
            status = 'Enrolled' if voter.enrolled else 'Not enrolled'
        else:
            status = 'Not found'
    return render_template('check_enrolment.html', status=status)

@app.route('/self_enrol', methods=['GET', 'POST'])
def self_enrol():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        voter = Voter.query.filter_by(name=name).first()
        if voter:
            voter.enrolled = True
            voter.address = address
            db.session.commit()
            get_audit_logger().log('enrol_update', actor=name, details={'address': address, 'existing': True})
            flash('You are now enrolled!')
        else:
            voter = Voter(name=name, address=address, enrolled=True)
            db.session.add(voter)
            db.session.commit()
            get_audit_logger().log('enrol_create', actor=name, details={'address': address})
            flash('Enrolled successfully!')
        return redirect(url_for('index'))
    return render_template('self_enrol.html')

@app.route('/update_address', methods=['GET', 'POST'])
def update_address():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        voter = Voter.query.filter_by(name=name).first()
        if voter:
            voter.address = address
            db.session.commit()
            get_audit_logger().log('update_address', actor=name, details={'address': address})
            flash('Address updated!')
        else:
            flash('Voter not found!')
        return redirect(url_for('index'))
    return render_template('update_address.html')

# Candidate Management
@app.route('/add_candidate', methods=['GET', 'POST'])
@role_required('admin', 'clerk')  # Theo: Issue 8 - allow clerks and admins to manage candidates
def add_candidate():
    if request.method == 'POST':
        name = request.form['name']
        party = request.form['party']
        order_val = request.form.get('order', None)
        order = int(order_val) if order_val not in (None, "",) else None
        candidate = Candidate(name=name, party=party, order=order)
        db.session.add(candidate)
        db.session.commit()
        actor = (_current_user().username if _current_user() else 'system')
        get_audit_logger().log('add_candidate', actor=actor, details={'name': name, 'party': party, 'order': order})
        _cache_invalidate('candidates:')  # Requirement 14: bust cache on mutation
        flash('Candidate added!')
        return redirect(url_for('index'))
    return render_template('add_candidate.html')

@app.route('/candidates')
def candidates():
    # Requirement 14: cache common data
    key = 'candidates:list'
    cached, hit = _cache_get(key)
    if hit:
        candidates = cached
    else:
        candidates = Candidate.query.order_by(Candidate.party, Candidate.order).all()
        _cache_set(key, candidates, app.config.get('CACHE_TTL_CANDIDATES', 60))
    return render_template('candidates.html', candidates=candidates)

# Voters list (enrolled only)
@app.route('/voters')
def voters():
    voters = Voter.query.filter_by(enrolled=True).order_by(Voter.name.asc()).all()
    return render_template('voters.html', voters=voters)

# Voting Process
@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if not is_country_allowed():
        flash('Voting not allowed from your region')
        return abort(403)
    voters = Voter.query.filter_by(enrolled=True).all()
    candidates = Candidate.query.all()
    if request.method == 'POST':
        voter_id = int(request.form['voter_id'])
        house_preferences = _sanitize_csv_numbers(request.form.get('house_preferences', ''))
        senate_above = _sanitize_csv_words(request.form.get('senate_above', ''))
        senate_below = _sanitize_csv_numbers(request.form.get('senate_below', ''))
        # Validate voter eligibility and one-vote rule
        voter = Voter.query.get(voter_id)
        if not voter or not voter.enrolled:
            flash('Voter not eligible to vote.')
            return redirect(url_for('vote'))
        existing = Vote.query.filter_by(voter_id=voter_id).first()
        if existing:
            flash('This voter has already voted.')
            return redirect(url_for('vote'))

        # Gurveen - Issue #1: encrypt ballot selections before saving so they never rest in plaintext.
        vote_obj = Vote(
            voter_id=voter_id,
            house_preferences=encrypt_ballot_value(house_preferences.strip()),
            senate_above=encrypt_ballot_value(senate_above.strip()),
            senate_below=encrypt_ballot_value(senate_below.strip()),
            source="electronic"
        )
        db.session.add(vote_obj)
        db.session.commit()
        # Requirement 10: Generate metadata-based receipt
        receipt = _generate_receipt(vote_obj, source="electronic")
        db.session.add(VoteReceipt(vote_id=vote_obj.id, receipt=receipt))
        db.session.commit()
        get_audit_logger().log('submit_vote', actor=str(voter_id), details={'vote_id': vote_obj.id})
        return render_template('vote_receipt.html', receipt=receipt)
    return render_template('vote.html', voters=voters, candidates=candidates)

# Overseas voting with mission code gate (prototype)
@app.route('/vote_overseas', methods=['GET', 'POST'])
def vote_overseas():
    # Geolocation: still enforce region policy for overseas page too
    if not is_country_allowed():
        flash('Voting not allowed from your region')
        return abort(403)
    voters = Voter.query.filter_by(enrolled=True).all()
    candidates = Candidate.query.all()
    if request.method == 'POST':
        mission = request.form.get('mission_code', '').strip().upper()
        if mission not in ALLOWED_MISSIONS:
            flash('Overseas voting restricted to Australian missions. Invalid mission code.')
            return redirect(url_for('vote_overseas'))

        voter_id = int(request.form['voter_id'])
        house_preferences = _sanitize_csv_numbers(request.form.get('house_preferences', ''))
        senate_above = _sanitize_csv_words(request.form.get('senate_above', ''))
        senate_below = _sanitize_csv_numbers(request.form.get('senate_below', ''))

        voter = Voter.query.get(voter_id)
        if not voter or not voter.enrolled:
            flash('Voter not eligible to vote.')
            return redirect(url_for('vote_overseas'))
        existing = Vote.query.filter_by(voter_id=voter_id).first()
        if existing:
            flash('This voter has already voted.')
            return redirect(url_for('vote_overseas'))

        # Gurveen - Issue #1: re-use AES protection for overseas ballots.
        vote_obj = Vote(
            voter_id=voter_id,
            house_preferences=encrypt_ballot_value(house_preferences.strip()),
            senate_above=encrypt_ballot_value(senate_above.strip()),
            senate_below=encrypt_ballot_value(senate_below.strip()),
            source="electronic"
        )
        db.session.add(vote_obj)
        db.session.commit()
        receipt = _generate_receipt(vote_obj, source="electronic")
        db.session.add(VoteReceipt(vote_id=vote_obj.id, receipt=receipt))
        db.session.commit()
        get_audit_logger().log('submit_vote_overseas', actor=str(voter_id), details={'vote_id': vote_obj.id, 'mission': mission})
        return render_template('vote_receipt.html', receipt=receipt)
    return render_template('vote_overseas.html', voters=voters, candidates=candidates, missions=sorted(ALLOWED_MISSIONS))

# Results Computation
@app.route('/results')
def results():
    # Naive tallies for prototype purposes
    all_votes = Vote.query.all()
    house_tally = {}
    senate_party_tally = {}
    senate_candidate_tally = {}

    for v in all_votes:
        # Gurveen - Issue #1: decrypt inside memory to keep database and backups unlinkable.
        house_plain = decrypt_ballot_value(v.house_preferences)
        senate_above_plain = decrypt_ballot_value(v.senate_above)
        senate_below_plain = decrypt_ballot_value(v.senate_below)

        # House: count first preference only (prototype simplification)
        if house_plain:
            firsts = [s for s in house_plain.split(',') if s.strip()]
            if firsts:
                first = firsts[0].strip()
                house_tally[first] = house_tally.get(first, 0) + 1
        # Senate above the line: count one per party listed (prototype)
        if senate_above_plain:
            for p in [s.strip() for s in senate_above_plain.split(',') if s.strip()]:
                senate_party_tally[p] = senate_party_tally.get(p, 0) + 1
        # Senate below the line: count first preference only (prototype)
        if senate_below_plain:
            firsts_b = [s for s in senate_below_plain.split(',') if s.strip()]
            if firsts_b:
                first_b = firsts_b[0].strip()
                senate_candidate_tally[first_b] = senate_candidate_tally.get(first_b, 0) + 1

    # Resolve IDs to names for readability where possible
    def candidate_name(cid):
        try:
            c = Candidate.query.get(int(cid))
            return f"{c.name} ({c.party})" if c else str(cid)
        except Exception:
            return str(cid)

    house_display = sorted([(candidate_name(k), v) for k, v in house_tally.items()], key=lambda x: x[1], reverse=True)
    senate_party_display = sorted(senate_party_tally.items(), key=lambda x: x[1], reverse=True)
    senate_candidate_display = sorted([(candidate_name(k), v) for k, v in senate_candidate_tally.items()], key=lambda x: x[1], reverse=True)

    # Requirement 14: cache results aggregates in-memory briefly
    # Note: since votes are rare, we recompute per request for correctness and rely on browser cache headers.
    return render_template(
        'results.html',
        house_display=house_display,
        senate_party_display=senate_party_display,
        senate_candidate_display=senate_candidate_display,
        total_votes=len(all_votes)
    )

# Import scanned paper ballot results (CSV paste for prototype)
@app.route('/import_scanned', methods=['GET', 'POST'])
@role_required('admin')  # Theo: Issue 8 - API RBAC: restrict import to admins
def import_scanned():
    if request.method == 'POST':
        data = request.form.get('csv_data', '').strip()
        count = 0
        for line in data.splitlines():
            parts = [p.strip() for p in line.split(';')]
            # Expected simple format: house_prefs;senate_above;senate_below
            if not parts:
                continue
            hp = parts[0] if len(parts) > 0 else ''
            sa = parts[1] if len(parts) > 1 else ''
            sb = parts[2] if len(parts) > 2 else ''
            # Scanned ballots have no voter id; store with voter_id=0
            # Gurveen - Issue #1: ensure imported paper ballots are encrypted identically to electronic ones.
            v = Vote(
                voter_id=0,
                house_preferences=encrypt_ballot_value(hp),
                senate_above=encrypt_ballot_value(sa),
                senate_below=encrypt_ballot_value(sb),
                source='scanned'
            )
            db.session.add(v)
            count += 1
        db.session.commit()
        get_audit_logger().log('import_scanned', actor='admin', details={'count': count})
        flash(f'Imported {count} scanned ballots.')
        return redirect(url_for('results'))
    return render_template('import_scanned.html')

# Simple JSON results for external systems (prototype)
@app.route('/api/results')
def api_results():
    # Basic aggregation mirroring results() above
    all_votes = Vote.query.all()
    house_tally = {}
    senate_party_tally = {}
    senate_candidate_tally = {}
    for v in all_votes:
        house_plain = decrypt_ballot_value(v.house_preferences)
        senate_above_plain = decrypt_ballot_value(v.senate_above)
        senate_below_plain = decrypt_ballot_value(v.senate_below)

        if house_plain:
            firsts = [s for s in house_plain.split(',') if s.strip()]
            if firsts:
                first = firsts[0].strip()
                house_tally[first] = house_tally.get(first, 0) + 1
        if senate_above_plain:
            for p in [s.strip() for s in senate_above_plain.split(',') if s.strip()]:
                senate_party_tally[p] = senate_party_tally.get(p, 0) + 1
        if senate_below_plain:
            firsts_b = [s for s in senate_below_plain.split(',') if s.strip()]
            if firsts_b:
                first_b = firsts_b[0].strip()
                senate_candidate_tally[first_b] = senate_candidate_tally.get(first_b, 0) + 1

    return jsonify({
        'house_first_pref_tally': house_tally,
        'senate_party_tally': senate_party_tally,
        'senate_candidate_first_pref_tally': senate_candidate_tally,
        'total_votes': len(all_votes)
    })

# Manual exclusion recount (prototype): ignore listed candidate IDs in tallies
@app.route('/recount', methods=['GET', 'POST'])
@role_required('admin', 'clerk')
def recount():
    excluded = set()
    if request.method == 'POST':
        raw = request.form.get('exclude_ids', '')
        excluded = {s.strip() for s in raw.split(',') if s.strip()}

    all_votes = Vote.query.all()
    house_tally = {}
    senate_party_tally = {}
    senate_candidate_tally = {}
    for v in all_votes:
        decrypted_house = decrypt_ballot_value(v.house_preferences)
        decrypted_senate_above = decrypt_ballot_value(v.senate_above)
        decrypted_senate_below = decrypt_ballot_value(v.senate_below)

        if decrypted_house:
            prefs = [s.strip() for s in decrypted_house.split(',') if s.strip()]
            prefs = [p for p in prefs if p not in excluded]
            if prefs:
                house_tally[prefs[0]] = house_tally.get(prefs[0], 0) + 1
        if decrypted_senate_above:
            for p in [s.strip() for s in decrypted_senate_above.split(',') if s.strip()]:
                senate_party_tally[p] = senate_party_tally.get(p, 0) + 1
        if decrypted_senate_below:
            prefs_b = [s.strip() for s in decrypted_senate_below.split(',') if s.strip()]
            prefs_b = [p for p in prefs_b if p not in excluded]
            if prefs_b:
                senate_candidate_tally[prefs_b[0]] = senate_candidate_tally.get(prefs_b[0], 0) + 1

    def candidate_name(cid):
        try:
            c = Candidate.query.get(int(cid))
            return f"{c.name} ({c.party})" if c else str(cid)
        except Exception:
            return str(cid)

    house_display = sorted([(candidate_name(k), v) for k, v in house_tally.items()], key=lambda x: x[1], reverse=True)
    senate_party_display = sorted(senate_party_tally.items(), key=lambda x: x[1], reverse=True)
    senate_candidate_display = sorted([(candidate_name(k), v) for k, v in senate_candidate_tally.items()], key=lambda x: x[1], reverse=True)

    return render_template('recount.html',
                           excluded=','.join(sorted(excluded)) if excluded else '',
                           house_display=house_display,
                            senate_party_display=senate_party_display,
                            senate_candidate_display=senate_candidate_display)

# Vote verifiability endpoint
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    status = None
    if request.method == 'POST':
        receipt = request.form.get('receipt', '').strip()
        status = 'not_found'
        if receipt:
            vr = VoteReceipt.query.filter_by(receipt=receipt).first()
            if vr:
                status = 'counted'
    return render_template('verify.html', status=status)


# Requirement 17: Admin-triggered backup (hybrid local + simulated cloud)
def _export_backup_payload():
    def voter_row(v: Voter):
        return {'id': v.id, 'name': v.name, 'address': v.address, 'enrolled': bool(v.enrolled)}
    def candidate_row(c: Candidate):
        return {'id': c.id, 'name': c.name, 'party': c.party, 'order': c.order}
    def vote_row(v: Vote):
        return {
            'id': v.id,
            'voter_id': v.voter_id,
            'house_preferences': v.house_preferences,
            'senate_above': v.senate_above,
            'senate_below': v.senate_below,
            'source': v.source,
        }
    def receipt_row(r: VoteReceipt):
        return {'id': r.id, 'vote_id': r.vote_id, 'receipt': r.receipt}
    def user_row(u: 'UserAccount'):
        return {'id': u.id, 'username': u.username, 'role': u.role, 'mfa_enabled': bool(u.mfa_enabled), 'is_eligible': bool(u.is_eligible)}

    payload = {
        'ts': datetime.utcnow().isoformat() + 'Z',
        'voters': [voter_row(v) for v in Voter.query.all()],
        'candidates': [candidate_row(c) for c in Candidate.query.all()],
        'votes': [vote_row(v) for v in Vote.query.all()],
        'receipts': [receipt_row(r) for r in VoteReceipt.query.all()],
        'users': [user_row(u) for u in UserAccount.query.all()],
    }
    return payload


@app.route('/admin/backup', methods=['POST', 'GET'])
@role_required('admin')
def admin_backup():
    os.makedirs(app.config.get('BACKUP_LOCAL_DIR'), exist_ok=True)
    os.makedirs(app.config.get('BACKUP_CLOUD_DIR'), exist_ok=True)
    payload = _export_backup_payload()
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    fname = f"backup-{ts}.json"
    local_path = os.path.join(app.config.get('BACKUP_LOCAL_DIR'), fname)
    cloud_path = os.path.join(app.config.get('BACKUP_CLOUD_DIR'), fname)
    with open(local_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
    with open(cloud_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
    return jsonify({'ok': True, 'local': local_path, 'cloud': cloud_path})


# Requirement 20: URL validation and test endpoint
from urllib.parse import urlparse

def _is_safe_url(url: str) -> bool:
    if not url:
        return False
    p = urlparse(url)
    # allow relative URLs
    if not p.netloc:
        return True
    if p.scheme not in {'http', 'https'}:
        return False
    allowed = set(app.config.get('ALLOWED_REDIRECT_HOSTS') or [])
    return p.hostname in allowed


@app.route('/url_validation_test')
@role_required('admin')
def url_validation_test():
    test_url = request.args.get('url', '')
    return jsonify({'url': test_url, 'allowed': _is_safe_url(test_url)})


@app.route('/cache_test')
@role_required('admin')
def cache_test():
    # Surface whether candidates list is currently cached
    _, hit = _cache_get('candidates:list')
    return jsonify({'candidates_cache_hit': hit, 'ttl_candidates': app.config.get('CACHE_TTL_CANDIDATES', 60)})


# Audit log verification (admin)
@app.route('/audit/verify')
@role_required('admin')  # Theo: Issue 8 - API RBAC: admin-only audit verification
def audit_verify():
    ok = get_audit_logger().verify()
    return jsonify({'audit_log_valid': ok})


# Gurveen - Issue #4: admin-only UI harness to validate audit log signatures (testing purposes only).
@app.route('/audit/signature-test')
@role_required('admin')
def audit_signature_test():
    logger = get_audit_logger()
    chain_ok = logger.verify()
    signature_manager = get_signature_manager()
    log_path = app.config.get('AUDIT_LOG_PATH')
    entries = []
    log_error = None
    try:
        with open(log_path, 'r', encoding='utf-8') as audit_file:
            for raw in audit_file:
                record_line = raw.strip()
                if not record_line:
                    continue
                try:
                    record = json.loads(record_line)
                except json.JSONDecodeError:
                    entries.append({
                        'timestamp': 'n/a',
                        'actor': None,
                        'action': None,
                        'signature_valid': False,
                        'sig_issue': 'Malformed audit entry payload',
                        'signature_alg': None,
                        'public_key': None,
                        'signature': None,
                        'mac': None,
                    })
                    continue
                base_payload = {
                    key: record[key]
                    for key in record
                    if key not in {'signature', 'signing_public_key', 'signature_alg'}
                }
                signature_alg = record.get('signature_alg')
                signature = record.get('signature')
                public_key = record.get('signing_public_key')
                signature_valid = False
                sig_issue = None
                if signature_alg != 'ed25519':
                    sig_issue = 'Unsupported signature algorithm'
                elif not signature or not public_key:
                    sig_issue = 'Missing signature or public key'
                else:
                    sign_body = json.dumps(base_payload, sort_keys=True).encode('utf-8')
                    signature_valid = signature_manager.verify_signature(public_key, sign_body, signature)
                    if not signature_valid:
                        sig_issue = 'Signature verification failed'
                ts = record.get('ts')
                timestamp = (
                    datetime.utcfromtimestamp(ts).isoformat() + 'Z'
                    if isinstance(ts, (int, float)) and ts > 0 else 'n/a'
                )
                entries.append({
                    'timestamp': timestamp,
                    'actor': record.get('actor', 'system'),
                    'action': record.get('action'),
                    'signature_valid': signature_valid,
                    'sig_issue': sig_issue,
                    'signature_alg': signature_alg,
                    'public_key': public_key,
                    'signature': signature,
                    'mac': record.get('mac'),
                })
    except FileNotFoundError:
        log_error = 'Audit log file not found yet.'
    except Exception as exc:  # pragma: no cover - defensive
        log_error = f'Unexpected error reading audit log: {exc}'
    latest_entries = list(reversed(entries[-25:]))
    return render_template(
        'audit_signature_test.html',
        chain_ok=chain_ok,
        entries=latest_entries,
        log_error=log_error,
    )


# Gurveen - Issue #2: Public UI for running TLS and vote integrity diagnostics (testing only)
@app.route('/integrity_test', methods=['GET', 'POST'])
def integrity_test():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'reset_audit_log':
            log_path = app.config.get('AUDIT_LOG_PATH')
            try:
                if log_path and os.path.exists(log_path):
                    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                    backup_path = f"{log_path}.bak.{ts}"
                    os.replace(log_path, backup_path)
                    flash(f'Audit log reset for testing (backup saved as {os.path.basename(backup_path)}).')
                else:
                    flash('Audit log not found; nothing to reset.')
            except Exception as exc:  # pragma: no cover - defensive
                flash(f'Failed to reset audit log: {exc}')
        return redirect(url_for('integrity_test'))

    tests = []

    def add_test(name: str, passed: bool, detail: str = ""):
        tests.append({
            'name': name,
            'passed': bool(passed),
            'detail': detail
        })

    tls_configured = bool(app.config.get('TLS_ENABLE'))
    add_test('TLS configuration enabled', tls_configured, 'TLS_ENABLE flag is set to true in server configuration.' if tls_configured else 'TLS_ENABLE is false; HTTPS should be enabled before production use.')

    forwarded_proto = (request.headers.get('X-Forwarded-Proto', '') or '').lower()
    tls_in_use = request.is_secure or forwarded_proto == 'https'
    add_test('Current session using HTTPS', tls_in_use, 'Request arrived over HTTPS.' if tls_in_use else 'Current request is not HTTPS; ensure TLS termination in front of Flask.')

    audit_ok = get_audit_logger().verify()
    add_test('Tamper-evident audit log chain valid', audit_ok, 'Audit log hash chain is intact.' if audit_ok else 'Audit log verification failed; past entries may have been altered.')

    ballots_intact = True
    ballots_detail = 'All encrypted ballots decrypted successfully.'
    try:
        votes = Vote.query.all()
        for vote in votes:
            for field in ('house_preferences', 'senate_above', 'senate_below'):
                payload = getattr(vote, field)
                if payload:
                    try:
                        decrypt_ballot_value(payload)
                    except Exception as exc:  # pragma: no cover - defensive
                        ballots_intact = False
                        ballots_detail = f"Decryption failed for vote #{vote.id} field '{field}': {exc}"
                        raise
    except Exception:
        ballots_intact = False
    add_test('Encrypted ballots decrypt correctly', ballots_intact, ballots_detail if ballots_intact else ballots_detail)

    return render_template('integrity_test.html', tests=tests, tls_configured=tls_configured)


@limiter.exempt  # Gurveen - Issue #3: diagnostics must not consume production quota.
@app.route('/rate_limit_test')
@role_required('admin')
def rate_limit_test():
    # Gurveen - Issue #3: UI harness verifies rate limiter health before election day.
    storage = limiter.limiter.storage
    storage_backend = storage.__class__.__name__
    storage_uri = app.config.get('RATE_LIMIT_STORAGE_URI', 'memory://')
    storage_ok = True
    storage_detail = 'Operational'
    try:
        check_fn = getattr(storage, 'check', None)
        if callable(check_fn):
            storage_ok = bool(check_fn())
            storage_detail = 'Connected' if storage_ok else 'Unreachable'
    except Exception as exc:  # pragma: no cover - defensive
        storage_ok = False
        storage_detail = f'Error: {exc}'
    if storage_uri.startswith('memory://'):
        storage_detail = 'Warning: In-memory storage cannot protect across multiple containers.'
    limit_policy = app.config.get('RATE_LIMIT_DEFAULT') or '50 per minute'
    return render_template(
        'rate_limit_test.html',
        limit_policy=limit_policy,
        storage_uri=storage_uri,
        storage_backend=storage_backend,
        storage_ok=storage_ok,
        storage_detail=storage_detail
    )


@limiter.exempt  # Gurveen - Issue #3: allow frequent polling without tripping limiter.
@app.route('/rate_limit_test/window')
@role_required('admin')
def rate_limit_test_window():
    # Gurveen - Issue #3: Surface remaining allowance for the tester's IP.
    limit_item = _default_rate_limit_item()
    test_token = f"ui-rate-limit::{_resolve_client_ip()}"
    reset_at, remaining = limiter.limiter.get_window_stats(limit_item, test_token)
    reset_display = reset_at.isoformat() if hasattr(reset_at, 'isoformat') else reset_at
    return jsonify({
        'limit_policy': str(limit_item),
        'remaining': remaining,
        'window_resets_at': reset_display
    })


@limiter.exempt  # Gurveen - Issue #3: internal simulation should not be blocked by global caps.
@app.route('/rate_limit_test/hit', methods=['POST'])
@role_required('admin')
def rate_limit_test_hit():
    # Gurveen - Issue #3: Simulate a burst locally without hammering real vote endpoints
    payload = request.get_json(silent=True) or {}
    requested = int(payload.get('count', 1))
    requested = max(1, min(requested, 200))
    limit_item = _default_rate_limit_item()
    test_token = f"ui-rate-limit::{_resolve_client_ip()}"
    allowed = 0
    blocked = 0
    for _ in range(requested):
        if limiter.limiter.hit(limit_item, test_token):
            allowed += 1
        else:
            blocked = requested - allowed
            break
    reset_at, remaining = limiter.limiter.get_window_stats(limit_item, test_token)
    reset_display = reset_at.isoformat() if hasattr(reset_at, 'isoformat') else reset_at
    return jsonify({
        'requested': requested,
        'allowed': allowed,
        'blocked': blocked,
        'remaining': remaining,
        'limit_policy': str(limit_item),
        'window_resets_at': reset_display
    })


@limiter.exempt  # Gurveen - Issue #3: let QA reset diagnostics as needed.
@app.route('/rate_limit_test/reset', methods=['POST'])
@role_required('admin')
def rate_limit_test_reset():
    """Gurveen - Issue #3: Clear the synthetic test window so QA can rerun scenarios."""
    limit_item = _default_rate_limit_item()
    test_token = f"ui-rate-limit::{_resolve_client_ip()}"
    reset_fn = getattr(limiter.limiter, 'reset', None)
    if callable(reset_fn):
        reset_fn(limit_item, test_token)
    else:  # pragma: no cover - legacy fallback
        clear_fn = getattr(limiter.limiter, 'clear', None)
        if callable(clear_fn):
            clear_fn(limit_item, test_token)
    reset_at, remaining = limiter.limiter.get_window_stats(limit_item, test_token)
    reset_display = reset_at.isoformat() if hasattr(reset_at, 'isoformat') else reset_at
    return jsonify({
        'limit_policy': str(limit_item),
        'remaining': remaining,
        'window_resets_at': reset_display
    })


@app.route('/encryption_diagnostics')
@role_required('admin')
def encryption_diagnostics():
    if not _encryption_diagnostics_enabled():
        return abort(404)

    # Gurveen - Issue #1: display how AES wraps ballots, while warning this view is for test-only usage.
    sample_plain = "1,2,3"
    sample_cipher = encrypt_ballot_value(sample_plain)

    latest_vote = Vote.query.order_by(Vote.id.desc()).first()
    stored_cipher = latest_vote.house_preferences if latest_vote else ""
    stored_plain = decrypt_ballot_value(stored_cipher) if stored_cipher else ""

    return render_template(
        'encryption_diagnostics.html',
        sample_plain=sample_plain,
        sample_cipher=sample_cipher,
        stored_cipher=stored_cipher,
        stored_plain=stored_plain,
        diagnostics_enabled=True,
        latest_vote_id=latest_vote.id if latest_vote else None
    )

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # Gurveen - Issue #2: Enable HTTPS using Python stdlib only when configured.
    # In production, prefer terminating TLS at a reverse proxy (e.g., nginx/Load Balancer)
    # and keep Flask behind it. This path supports dev/self-hosted TLS.
    cert = app.config.get('TLS_CERT_FILE')
    key = app.config.get('TLS_KEY_FILE')
    enable_tls = app.config.get('TLS_ENABLE', False) and cert and key
    if enable_tls:
        _ensure_self_signed_certificates(cert, key)
    ssl_ctx = (cert, key) if enable_tls else None
    # Gurveen - Issue #2: When TLS is enabled, set secure cookies if not already forced by env
    if enable_tls:
        app.config['SESSION_COOKIE_SECURE'] = True
    app.run(host="0.0.0.0", ssl_context=ssl_ctx)
