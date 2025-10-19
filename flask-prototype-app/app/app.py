from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
import os
import uuid
from flask_sqlalchemy import SQLAlchemy
# Support running as a script or as a package
try:
    from security import get_audit_logger, is_country_allowed  # when running app/app.py directly
except ImportError:  # pragma: no cover
    from .security import get_audit_logger, is_country_allowed  # when imported as package

app = Flask(__name__)
# Avoid import-time package/module name conflicts by loading config from file path
_basedir = os.path.dirname(__file__)
app.config.from_pyfile(os.path.join(_basedir, 'config.py'))
db = SQLAlchemy(app)

# Simple list of allowed mission codes for overseas voting (prototype)
ALLOWED_MISSIONS = {"AUS-LONDON", "AUS-WASHINGTON", "AUS-TOKYO", "AUS-SINGAPORE"}

# Ensure tables exist when running via `flask run` (not just `python app.py`)
@app.before_first_request
def _init_db():
    db.create_all()

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

# Routes

@app.route('/')
def index():
    return render_template('index.html')

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

        vote_obj = Vote(
            voter_id=voter_id,
            house_preferences=house_preferences.strip(),
            senate_above=senate_above.strip(),
            senate_below=senate_below.strip(),
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

        vote_obj = Vote(
            voter_id=voter_id,
            house_preferences=house_preferences.strip(),
            senate_above=senate_above.strip(),
            senate_below=senate_below.strip(),
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
        # House: count first preference only (prototype simplification)
        if v.house_preferences:
            firsts = [s for s in v.house_preferences.split(',') if s.strip()]
            if firsts:
                first = firsts[0].strip()
                house_tally[first] = house_tally.get(first, 0) + 1
        # Senate above the line: count one per party listed (prototype)
        if v.senate_above:
            for p in [s.strip() for s in v.senate_above.split(',') if s.strip()]:
                senate_party_tally[p] = senate_party_tally.get(p, 0) + 1
        # Senate below the line: count first preference only (prototype)
        if v.senate_below:
            firsts_b = [s for s in v.senate_below.split(',') if s.strip()]
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
            v = Vote(voter_id=0, house_preferences=hp, senate_above=sa, senate_below=sb, source='scanned')
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
        if v.house_preferences:
            firsts = [s for s in v.house_preferences.split(',') if s.strip()]
            if firsts:
                first = firsts[0].strip()
                house_tally[first] = house_tally.get(first, 0) + 1
        if v.senate_above:
            for p in [s.strip() for s in v.senate_above.split(',') if s.strip()]:
                senate_party_tally[p] = senate_party_tally.get(p, 0) + 1
        if v.senate_below:
            firsts_b = [s for s in v.senate_below.split(',') if s.strip()]
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
        if v.house_preferences:
            prefs = [s.strip() for s in v.house_preferences.split(',') if s.strip()]
            prefs = [p for p in prefs if p not in excluded]
            if prefs:
                house_tally[prefs[0]] = house_tally.get(prefs[0], 0) + 1
        if v.senate_above:
            for p in [s.strip() for s in v.senate_above.split(',') if s.strip()]:
                senate_party_tally[p] = senate_party_tally.get(p, 0) + 1
        if v.senate_below:
            prefs_b = [s.strip() for s in v.senate_below.split(',') if s.strip()]
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
def audit_verify():
    ok = get_audit_logger().verify()
    return jsonify({'audit_log_valid': ok})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0")
