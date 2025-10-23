# Electronic Voting Prototype (Flask)

Basic working prototype for an Australian federal election e-voting system covering the functional requirements: enrolment, candidate management, voting for House and Senate (ATL/BTL), simple results, import of scanned ballots, and a JSON results API.

## Project Structure

```
flask-prototype-app
├─ app
│  ├─ app.py               # main app, models + routes
│  ├─ config.py            # defaults to SQLite, supports DATABASE_URL
│  ├─ crypto_utils.py      # AES helpers
│  ├─ static/style.css
│  └─ templates/
│     ├─ index.html
│     ├─ encryption_diagnostics.html
│     └─ ...
├─ docker-entrypoint.sh   #automation for docker
├─ docker-compose.yml
├─ Dockerfile
├─ requirements.txt
└─ README.md
```

## Quick Start (Docker)

The repository is pre-configured for a Docker-only demo workflow; only the security diagnostics require admin login.

> **Default Accounts (fixed in `app/config.py`)**  
> - Admin — username `admin`, password `SecureAdm#12`  
> - Clerk — username `clerk`, password `Clerk#12AB34`  
> - Voter — username `voter`, password `Voter#56CD78`  

Use the admin account for the diagnostic dashboards; clerk and voter accounts help exercise RBAC flows.

```bash
docker compose up --build
```

Point your browser at [http://localhost:5000/home](http://localhost:5000/home). HAProxy fans traffic across two Flask replicas, so the site stays responsive even if one container restarts under load.

- `docker-entrypoint.sh` still auto-generates and persists an AES ballot key in `/app/.ballot_encryption_key` unless `BALLOT_ENCRYPTION_KEY` is already defined.
- `ENABLE_ENCRYPTION_DIAGNOSTICS` remains `1` so you can verify secrecy via the UI without extra steps.
- Issue 1-3 diagnostics now require the default admin credentials (`admin` / `SecureAdm#12`); core enrolment and voting flows stay open for quick demos.
- The compose file wiring: HAProxy (`gateway`) + two Flask app containers (`app_primary`, `app_secondary`) + Redis (shared rate limit counters) + MySQL master/replica. Remove `DATABASE_URL` if you prefer SQLite.

> **Need HTTPS?** Set `TLS_ENABLE=true` on the app containers (and supply cert/key paths) or terminate TLS at HAProxy by mounting a PEM bundle and adding a `bind *:5000 ssl crt /path/to/cert.pem` line. No paid services are required.

### Gurveen - Issue #3: Rate Limiting & DDoS Resilience

- A single IP is limited to **50 requests per minute** across the entire cluster. Counters live in Redis, so the rule survives restarts and covers every replica.
- Trust headers `CF-Connecting-IP` and `X-Forwarded-For` are honoured so real client IPs are enforced even behind HAProxy/CDN.
- `/healthz` stays exempt for orchestration so probes never block legitimate voters.
- Visit `/rate_limit_test` (link in the nav) after logging in as admin to run the built-in simulation harness. It verifies Redis reachability, shows remaining quota for your IP, and lets you trigger a 55-request burst against a diagnostic bucket without affecting production voters. **Testing only; still perform full-scale load tests.**
- Need to adjust the policy? Override `RATE_LIMIT_DEFAULT` (e.g. `30 per minute`) or inject route-specific caps with Flask-Limiter decorators.

### Verifying AES Encryption via the UI

1. After the stack starts, open [http://localhost:5000/home](http://localhost:5000/home) (or HTTPS if you re-enable TLS).
2. Cast a vote using the regular voting form.
3. Click the **Encryption Check** card on the home page (you will be prompted to log in as admin if you are not already authenticated).
4. The diagnostics view shows:
   - A sample plaintext and the corresponding AES-GCM ciphertext, demonstrating nonce randomness.
   - The most recent stored ballot, displaying both the encrypted database value and the decrypted plaintext rendered only in-memory.
5. When you finish testing, disable diagnostics by setting `ENABLE_ENCRYPTION_DIAGNOSTICS=0` (or removing it) in your deployment configuration so plaintext never appears in production.

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

## HTTPS/TLS (Vote Integrity In-Transit)

You can serve the app over HTTPS using only Python's built-in SSL support and locally generated certificates (no paid services required).

Steps:
- Generate a self-signed certificate for development:
  - OpenSSL example:
    `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"`
- Set environment variables so the app enables TLS:
  - `TLS_ENABLE=true`
  - `TLS_CERT_FILE=path/to/cert.pem`
  - `TLS_KEY_FILE=path/to/key.pem`
- Start the app directly so Flask uses the SSL context:
  `python -m app.app`

Notes:
- When TLS is enabled (including the Docker default), the app forces `Secure` session cookies, redirects HTTP to HTTPS, and adds HSTS headers.
- In production, terminate TLS at a reverse proxy/load balancer and keep Flask behind it, or provide real certs by environment without any paid dependency.

### Gurveen - Issue #2: Vote Integrity Test Dashboard (Testing Only)

- Open `/integrity_test` (linked in the main navigation) to run automated checks that confirm TLS is configured, the current session is using HTTPS, the tamper-evident audit log verifies, and encrypted ballots decrypt without errors.
- This screen is for testing and demonstration purposes only; it does **not** replace formal certification or external penetration testing. Use it to validate configurations during development before promoting changes.

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
