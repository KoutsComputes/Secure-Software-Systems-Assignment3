# Electronic Voting Prototype (Flask)

Basic working prototype for an Australian federal election e-voting system covering the functional requirements: enrolment, candidate management, voting for House and Senate (ATL/BTL), simple results, import of scanned ballots, and a JSON results API.

## Project Structure

```
flask-prototype-app
├─ app
│  ├─ app.py               # main app, models + routes
│  ├─ config.py            # defaults to SQLite, supports DATABASE_URL
│  ├─ crypto_utils.py      # Requirement 1 AES helpers
│  ├─ static/style.css
│  └─ templates/
│     ├─ index.html
│     ├─ encryption_diagnostics.html
│     └─ ...
├─ docker-entrypoint.sh    # Requirement 1 automation for Docker
├─ docker-compose.yml
├─ Dockerfile
├─ requirements.txt
└─ README.md
```

## Quick Start (Docker)

The repository is pre-configured for a Docker-only workflow; no manual key management or flags are required.

```bash
docker compose up --build
```

Then open [http://localhost:5000](http://localhost:5000).

Behind the scenes:
- `docker-entrypoint.sh` auto-generates and persists an AES ballot key (Requirement 1) in `/app/.ballot_encryption_key` unless `BALLOT_ENCRYPTION_KEY` is already defined.
- `ENABLE_ENCRYPTION_DIAGNOSTICS` is automatically set to `1` so you can verify secrecy via the UI without extra steps.
- The compose file wires the Flask app to MySQL, but you can remove `DATABASE_URL` and the database services to fall back to SQLite if desired.

### Verifying AES Encryption via the UI

1. After the stack starts, cast a vote using the regular voting form.
2. Navigate to **Encryption Check** on the home page (visible because diagnostics are enabled in Docker).
3. The diagnostics view shows:
   - A sample plaintext and the corresponding AES-GCM ciphertext, demonstrating nonce randomness.
   - The most recent stored ballot, displaying both the encrypted database value and the decrypted plaintext rendered only in-memory.
4. When you finish testing, disable diagnostics by setting `ENABLE_ENCRYPTION_DIAGNOSTICS=0` (or removing it) in your deployment configuration so plaintext never appears in production.

## Manual (Non-Docker) Setup

If you prefer running locally:

```bash
pip install -r requirements.txt
export BALLOT_ENCRYPTION_KEY=$(python3 - <<'PY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)
export ENABLE_ENCRYPTION_DIAGNOSTICS=1  # optional for UI verification
flask --app app.app:app run
```

## Features in this Prototype

- Voter enrolment: register, check status, self-enrol, update address
- Candidate management: add candidates, order within party groups, list view
- Voting: House preferences (comma-separated), Senate ATL (party names) and BTL (candidate IDs)
- Overseas voting: gated by mission codes (prototype list)
- Results: simple first-preference tallies; recount with manual exclusions
- Scanned ballots: import via CSV-like paste to include in results
- API: `GET /api/results` returns JSON tallies
- Requirement 1 diagnostics: opt-in UI proving at-rest encryption without touching the database directly

## Notes

- This is a minimal prototype. Real electoral counting (preferential/STV) and security hardening are out of scope.
- Admin/RBAC/MFA are not implemented; pages are open for demonstration.
