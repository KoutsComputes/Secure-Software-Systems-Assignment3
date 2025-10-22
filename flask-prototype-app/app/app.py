from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session  # Theo: Issue 6 - session for auth
import os
import uuid
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash  # Theo: Issue 6 - password hashing
import pyotp  # Theo: Issue 6 - TOTP MFA
import qrcode  # Theo: Issue 6 - QR code generation for TOTP setup
import base64  # Theo: Issue 6 - Encode QR image for template
from io import BytesIO  # Theo: Issue 6 - In-memory image buffer
# Support running as a script or as a package
try:
    from security import get_audit_logger, is_country_allowed  # when running app/app.py directly
    from crypto_utils import encrypt_ballot_value, decrypt_ballot_value
except ImportError:  # pragma: no cover
    from .security import get_audit_logger, is_country_allowed  # when imported as package
    from .crypto_utils import encrypt_ballot_value, decrypt_ballot_value  # Requirement 1: AES ballot helpers

app = Flask(__name__)
# Avoid import-time package/module name conflicts by loading config from file path
_basedir = os.path.dirname(__file__)
app.config.from_pyfile(os.path.join(_basedir, 'config.py'))
db = SQLAlchemy(app)

# Simple list of allowed mission codes for overseas voting (prototype)
ALLOWED_MISSIONS = {"AUS-LONDON", "AUS-WASHINGTON", "AUS-TOKYO", "AUS-SINGAPORE"}

def _encryption_diagnostics_enabled() -> bool:
    """Requirement 1: guard diagnostics so plaintext exposure only happens when explicitly allowed."""
    return bool(app.config.get('ENABLE_ENCRYPTION_DIAGNOSTICS'))

# Ensure tables exist when running via `flask run` (not just `python app.py`)
@app.before_first_request
def _init_db():
    db.create_all()
    # Theo: Issue 8 - Seed default roles (DB‑level RBAC)
    try:
        existing = {r.name for r in Role.query.all()}
    except Exception:
        existing = set()
    for rname, desc in (
        ('voter', 'Regular voter with minimal privileges'),
        ('clerk', 'Polling clerk: verify enrolment, assist voters'),
        ('admin', 'System admin: manage candidates and system areas'),
    ):
        if rname not in existing:
            db.session.add(Role(name=rname, description=desc))
    db.session.commit()
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

@app.context_processor
def _inject_feature_flags():
    return {
        'encryption_diagnostics_enabled': _encryption_diagnostics_enabled()
    }

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
    # Whitelisted endpoints that must remain accessible
    whitelist = {
        'auth_login', 'auth_register', 'auth_mfa_setup', 'auth_mfa_verify', 'auth_mfa_prompt',
        'auth_logout',  # Theo: Allow logout even if MFA not completed yet
        'healthz', 'static'
    }
    if request.endpoint in whitelist or (request.endpoint or '').startswith('static'):
        return
    user = _current_user()
    if not user:
        # Not logged in: send to login
        return redirect(url_for('auth_login'))
    if not user.mfa_enabled and request.endpoint not in {'auth_mfa_setup', 'auth_mfa_verify'}:
        # Enforce MFA setup first
        flash('MFA setup required before using the system.')
        return redirect(url_for('auth_mfa_setup'))
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
    # Simple inline admin UI (Theo)
    options = ''.join(f'<option value="{r.name}">{r.name}</option>' for r in roles)
    rows = ''.join(
        f'<tr><td>{u.username}</td><td>{u.role}</td>'
        f'<td><form method="post" style="display:inline">'
        f'<input type="hidden" name="username" value="{u.username}">' \
        f'<select name="role">{options}</select> <button type="submit">Change</button></form></td></tr>'
        for u in users
    )
    return f"""
    <!-- Theo: Issue 8 - Admin user role management -->
    <h2>Manage User Roles</h2>
    <table border="1" cellpadding="6">
      <tr><th>Username</th><th>Role</th><th>Action</th></tr>
      {rows}
    </table>
    <p><a href='{url_for('dashboard_admin')}'>Back to admin dashboard</a></p>
    """

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
@role_required('admin')  # Theo: Issue 8 - API RBAC enforcement (admin only)
def add_candidate():
    if request.method == 'POST':
        name = request.form['name']
        party = request.form['party']
        order_val = request.form.get('order', None)
        order = int(order_val) if order_val not in (None, "",) else None
        candidate = Candidate(name=name, party=party, order=order)
        db.session.add(candidate)
        db.session.commit()
        get_audit_logger().log('add_candidate', actor='admin', details={'name': name, 'party': party, 'order': order})
        flash('Candidate added!')
        return redirect(url_for('index'))
    return render_template('add_candidate.html')

@app.route('/candidates')
def candidates():
    candidates = Candidate.query.order_by(Candidate.party, Candidate.order).all()
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
        house_preferences = request.form.get('house_preferences', '')
        senate_above = request.form.get('senate_above', '')
        senate_below = request.form.get('senate_below', '')
        # Validate voter eligibility and one-vote rule
        voter = Voter.query.get(voter_id)
        if not voter or not voter.enrolled:
            flash('Voter not eligible to vote.')
            return redirect(url_for('vote'))
        existing = Vote.query.filter_by(voter_id=voter_id).first()
        if existing:
            flash('This voter has already voted.')
            return redirect(url_for('vote'))

        # Requirement 1: encrypt ballot selections before saving so they never rest in plaintext.
        vote_obj = Vote(
            voter_id=voter_id,
            house_preferences=encrypt_ballot_value(house_preferences.strip()),
            senate_above=encrypt_ballot_value(senate_above.strip()),
            senate_below=encrypt_ballot_value(senate_below.strip()),
            source="electronic"
        )
        db.session.add(vote_obj)
        db.session.commit()
        # Generate verifiable receipt (non-identifying)
        receipt = uuid.uuid4().hex
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
        house_preferences = request.form.get('house_preferences', '')
        senate_above = request.form.get('senate_above', '')
        senate_below = request.form.get('senate_below', '')

        voter = Voter.query.get(voter_id)
        if not voter or not voter.enrolled:
            flash('Voter not eligible to vote.')
            return redirect(url_for('vote_overseas'))
        existing = Vote.query.filter_by(voter_id=voter_id).first()
        if existing:
            flash('This voter has already voted.')
            return redirect(url_for('vote_overseas'))

        # Requirement 1: re-use AES protection for overseas ballots.
        vote_obj = Vote(
            voter_id=voter_id,
            house_preferences=encrypt_ballot_value(house_preferences.strip()),
            senate_above=encrypt_ballot_value(senate_above.strip()),
            senate_below=encrypt_ballot_value(senate_below.strip()),
            source="electronic"
        )
        db.session.add(vote_obj)
        db.session.commit()
        receipt = uuid.uuid4().hex
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
        # Requirement 1: decrypt inside memory to keep database and backups unlinkable.
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
            # Requirement 1: ensure imported paper ballots are encrypted identically to electronic ones.
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


# Audit log verification (admin)
@app.route('/audit/verify')
@role_required('admin')  # Theo: Issue 8 - API RBAC: admin-only audit verification
def audit_verify():
    ok = get_audit_logger().verify()
    return jsonify({'audit_log_valid': ok})


@app.route('/encryption_diagnostics')
def encryption_diagnostics():
    if not _encryption_diagnostics_enabled():
        return abort(404)

    # Requirement 1: display how AES wraps ballots, while warning this view is for test-only usage.
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
    app.run(host="0.0.0.0")
