Admin Access Requirement 

- All diagnostic (testing) pages require an authenticated admin session.
- Default admin credentials: username `admin`, password `SecureAdm#12`.
- Log in at `http://localhost:5000/auth/login` before running any of the tests below (MFA remains optional unless explicitly enforced).
- Additional accounts for RBAC testing: clerk (`clerk` / `Clerk#12AB34`) and voter (`voter` / `Voter#56CD78`).

Encryption Diagnostics - Issue 1 (Gurveen)

- Purpose
  - Validate that AES ballot confidentiality works and that the diagnostics UI is available only to authorised admin testers.

- Where the code is (Gurveen)
  - `flask-prototype-app/app/app.py` - `_init_db` seeds/resets the default admin password (`SecureAdm#12`).
  - `flask-prototype-app/app/app.py` - `/encryption_diagnostics` now has `@role_required('admin')`.
  - `flask-prototype-app/app/templates/index.html` - diagnostics card remains but redirects unauthorised users to login.
  - `flask-prototype-app/README.md` - updated to instruct testers to authenticate as admin.

- Setup
  - cd `flask-prototype-app`
  - `docker compose up --build`
  - Ensure `ENABLE_ENCRYPTION_DIAGNOSTICS=1` (entrypoint sets this automatically in Docker).
  - Sign in at `http://localhost:5000/auth/login` with `admin` / `SecureAdm#12` so the diagnostics view loads.

- Test (UI)
  1. After logging in, open `http://localhost:5000/home`.
  2. Cast a vote.
  3. Click the "Encryption Check" card to open diagnostics.
  4. Confirm the page shows a sample plaintext with AES-GCM ciphertext and the most recent stored ballot's ciphertext with the server-side decrypted plaintext.

- Troubleshooting
  - If the card does not appear, verify the diagnostics flag is enabled.
  - For production, disable diagnostics (`ENABLE_ENCRYPTION_DIAGNOSTICS=0`) to hide the page.

Integrity Check - Issue 2 (Gurveen)

- Purpose
  - Allow testers to validate TLS transport, audit-log tamper evidence, and encrypted ballot integrity from the UI without extra tooling.

- Where the code is (Gurveen)
  - `flask-prototype-app/app/app.py` - `integrity_test` route aggregates diagnostic checks and exposes a testing-only audit log reset.
  - `flask-prototype-app/app/templates/integrity_test.html` - renders the pass/fail table with disclaimer.
  - `flask-prototype-app/app/static/style.css` - styles the integrity panel and rows.
  - `flask-prototype-app/app/templates/base.html` - main navigation link for quick access.

- Setup
  - From repo root: `cd flask-prototype-app`
  - Start the stack with HTTPS enabled by default: `docker compose up --build`
  - Wait until the `web` container healthcheck passes.

- Tests
  1. Visit `https://localhost:5000/home` (accept the self-signed cert on first run).
  2. Click **Integrity Tests** in the top nav or go directly to `https://localhost:5000/integrity_test` (open access for testing only).
  3. Confirm table rows show **Pass**:
     - TLS configuration enabled (`TLS_ENABLE=true`).
     - Current session using HTTPS (`request.is_secure` or `X-Forwarded-Proto=https`).
     - Tamper-evident audit log chain valid (`TamperEvidentLogger.verify()`).
     - Encrypted ballots decrypt correctly (detects tampering/key mismatch).

- Troubleshooting
  - TLS failures -> ensure `/app/certs/server.crt` and `.key` exist; entrypoint and Issue #2 bootstrap regenerate them if missing.
  - Audit log failure -> inspect `/app/logs/audit.log` for manual edits; ensure `AUDIT_LOG_KEY` matches.
  - Ballot decryption failure -> confirm `/app/.ballot_encryption_key` matches deployed env or delete/allow regeneration.
  - Page unreachable -> verify container is running and `https://localhost:5000` is mapped.

- Disclaimer
  - This dashboard is for **testing purposes only**. Use the reset button solely in non-production environments; it preserves a backup copy for investigation before starting a fresh chain.

Availability and DDOS Resilience - Issue 3 (Gurveen)

- Purpose
  - Guarantee election-day uptime by validating that HAProxy, multiple Flask containers, Redis-backed rate limiting, work together to resist abusive traffic while keeping diagnostics restricted to admin testers.

- Where the code is (Gurveen)
  - `flask-prototype-app/app/app.py` - `rate_limit_test`, `rate_limit_test_hit`, `rate_limit_test_window`, and `rate_limit_test_reset` routes are all wrapped with `@role_required('admin')`, alongside `_resolve_client_ip` and limiter bootstrap.
  - `flask-prototype-app/app/templates/rate_limit_test.html` - UI harness for burst simulation and live quota display.
  - `flask-prototype-app/app/static/style.css` - styling for Issue #3 diagnostics cards and alerts.
  - `flask-prototype-app/docker-compose.yml` - HAProxy (`gateway`), dual app replicas, Redis store, MySQL tier.
  - `flask-prototype-app/docker-entrypoint.sh` - auto-configure rate limit defaults (50/min), Redis URI, self-signed TLS (optional).
  - `flask-prototype-app/README.md` - overview of the resilience architecture and tester warnings.

- Setup
  1. From repo root: `cd flask-prototype-app`
  2. Launch the stack: `docker compose up --build`
  3. Wait until `gateway`, `redis`, `app_primary`, and `app_secondary` show as **healthy** (`docker compose ps`).
  4. Log in as `admin` / `SecureAdm#12` to unlock the diagnostics dashboard.
  5. (Optional) Tail logs to confirm HAProxy is balancing requests: `docker compose logs -f gateway`.

- Tests
  1. **Cluster Health via UI**
     - Browse to `http://localhost:5000/rate_limit_test` (or use **Rate Limiter Tests** in the nav). Unauthenticated users are redirected to the login page.
     - Confirm summary cards show:
       - Policy = `50 per minute` (or your overridden value).
       - Storage backend = `RedisStorage` targeting `redis://redis:6379/0`.
       - Backend status = **Healthy**.
  2. **Burst Simulation**
     - Leave the default 55 requests and click **Launch Simulation**.
     - Expect the first ~50 requests to succeed, the remainder to be blocked, and the remaining quota to drop accordingly.
     - Observe the reset timer to understand when the next window opens.
  3. **Window Reset & Repeat**
     - Hit **Reset Window** to clear the diagnostic bucket (does not touch real voter traffic).
     - Re-run the burst to confirm consistent limiter behaviour.
  4. **Failover Check (optional)**
     - From another terminal: `docker compose restart app_primary`.
     - Refresh the diagnostics page while the container restarts. HAProxy should continue serving responses via `app_secondary`, and the limiter counters should remain intact because they live in Redis.
  5. **CLI Verification**
     - Inspect Redis keys to ensure counters are being created: `docker compose exec redis redis-cli keys "*rate-limit*"` (expected: diagnostic token keys appear after a burst).
     - Verify HAProxy backend status: `docker compose exec gateway bash -c "echo 'show servers state' | socat stdio /var/run/haproxy/admin.sock"` (requires `socat` inside the image; if unavailable, rely on logs).

- Troubleshooting
  - Backend unavailable -> Run `docker compose logs redis`; ensure the container is healthy. Without Redis, rate limiting falls back to memory and loses cross-container protection.
  - Burst never blocks -> Check `RATE_LIMIT_DEFAULT` is reasonable; confirm diagnostics endpoints are not bypassing HAProxy.
  - Requests still blocked after reset -> Browser caching can reuse stale JSON; hard refresh or use curl: `curl -X POST http://localhost:5000/rate_limit_test/reset`.
  - HAProxy reports down backends -> Verify the Flask health checks (`/healthz`) succeed; inspect Flask logs for startup errors.

- Disclaimer
  - These diagnostics are for **testing purposes only**. Combine them with full-scale load tests, chaos/latency drills, and independent security assessments before going live on election day.

Non-Repudiation - Issue 4 (Gurveen)

- Purpose
  - Provide election auditors and administrators with verifiable proof that every audited action (votes, configuration changes, privileged access) carries an Ed25519 digital signature, preventing signers from repudiating their actions later.

- Where the code is (Gurveen)
  - `flask-prototype-app/app/security.py` - `DigitalSignatureManager` manages key provisioning and verifies signatures during log replay.
  - `flask-prototype-app/app/app.py` - `_ensure_actor_signing_identity` seeds keys for each account; `/audit/signature-test` renders the verification dashboard.
  - `flask-prototype-app/app/templates/audit_signature_test.html` - admin-only UI showing recent entries, signature status, and truncated keys.
  - `flask-prototype-app/docker-entrypoint.sh` - bootstraps the signing key vault inside the container with secure permissions.

- Setup
  1. From repo root: `cd flask-prototype-app`
  2. Start the stack: `docker compose up --build`
  3. After the app container starts, confirm the signer vault exists: `docker compose exec app ls -l app/signing_keys`
  4. Log in as `admin` / `SecureAdm#12` so the admin dashboard is available.

- Tests
  1. Navigate to `http://localhost:5000/home` and authenticate as the admin.
  2. In the admin dashboard, select **Digital Signature Test (Admin)**. A warning banner reminds you this diagnostic is for testing-only use.
  3. Perform several actions (e.g., cast a vote, update a voter address, import scanned ballots). Refresh the Digital Signature Test page-new entries should appear with:
     - Signature Status for untampered entries.
     - `ed25519` listed under Signature Algorithm.
     - Truncated base64 values for the signature and public key columns.
  4. Confirm the "Hash Chain Integrity" panel shows a success message. If it reports failure, review `app/logs/audit.log` for unexpected edits.

- Disclaimer
  - The Digital Signature Test dashboard is provided for **testing purposes only**. Auditors should export the full log and validate signatures using independent tooling before formal certification.

Security Testing Guide - Incident Recovery (Issue 5)

- Purpose
  - Test Docker health status, ordered startup, and auto-restart using a single Compose-based solution.

- Where the code is (Theo)
  - flask-prototype-app/app/app.py:58 - adds `/healthz` endpoint.
  - flask-prototype-app/docker-compose.yml:15 - web restart policy + healthcheck + depends_on (healthy DB).
  - flask-prototype-app/docker-compose.yml:42 - db healthcheck.
  - flask-prototype-app/docker-compose.yml:67 - replica depends_on + healthcheck.

- Requirements
  - Docker Desktop or Docker Engine with Compose v2.
  - PowerShell (Windows) or curl.

- Test (flask-prototype-app only)
  - cd `flask-prototype-app`
  - Bring up: `docker compose up -d --force-recreate`
  - Check health:
    - PowerShell: `Invoke-RestMethod http://localhost:5000/healthz`
    - curl: `curl http://localhost:5000/healthz`
  - Auto-restart (web):
    - `docker compose exec web sh -c "kill 1"`
    - `docker compose ps` (web should return to "Up")
    - Restart count (PowerShell):
      - `$id = (docker compose ps -q web)`
      - `docker inspect -f "{{ .RestartCount }}" $id`
  - Ordered startup (db -> web):
    - `docker compose down`
    - `docker compose up -d`
    - `docker compose ps` (db becomes healthy first, then web shows healthy)

- Troubleshooting
  - Port 3306 already in use: stop other stacks using MySQL or change/remove the db `ports:` mapping.
  - Healthcheck failing does not restart by itself; restarts happen on process exit or Docker daemon restart.
  - If `depends_on: condition: service_healthy` is ignored, update Docker Compose to v2.

MFA Testing Guide - Voter Authentication (Issue 6)

- Purpose
  - Verify password login and TOTP MFA using Microsoft/Google Authenticator.

- Where the code is (Theo)
  - flask-prototype-app/requirements.txt - `pyotp` added.
  - flask-prototype-app/app/app.py - `UserAccount` model; auth routes; `/secure/vote`.
  - flask-prototype-app/app/config.py - session cookie hardening; `ENFORCE_MFA_ON_VOTE` flag.
  - flask-prototype-app/app/templates/auth_*.html - simple forms.

- Setup
  - cd `flask-prototype-app`
  - `docker compose down`
  - `docker compose up -d --build`

- Register and Login
  - Open `http://localhost:5000/auth/register` -> create account (password %Y 12 chars)
  - Open `http://localhost:5000/auth/login` -> sign in

- MFA Setup (Microsoft/Google Authenticator)
  - Open `http://localhost:5000/auth/mfa-setup`
  - Scan the on-page QR code with Microsoft/Google Authenticator (or add the otpauth URI/secret manually)
  - Enter the 6-digit code to enable MFA

- MFA Login
  - Visit `http://localhost:5000/auth/logout` then `http://localhost:5000/auth/login`
  - After password, enter the 6-digit TOTP at `/auth/mfa`
  - Note: Admin users log in straight to the dashboard (MFA bypass for admin is enabled for testing convenience). Use a voter account to exercise the MFA prompt.

- Vote with MFA enforced
  - Use `http://localhost:5000/secure/vote` to exercise the protected flow
  - Optional: enforce on original `/vote` by uncommenting `ENFORCE_MFA_ON_VOTE=true` in compose and `docker compose up -d`
  - Strict behavior when flag is ON (Theo):
    - You must be logged in.
    - If you have not set up MFA yet, you will be redirected to `/auth/mfa-setup` before voting.
    - If you have MFA set up but not yet verified this session, you will be redirected to `/auth/mfa`.

- Troubleshooting
  - If codes don't verify, check device time is accurate and retry within 30s window.

Frontend RBAC Testing - Issue 7 (Theo)

- Purpose
  - Verify separate dashboards and visibility based on role without JWT.

- Where the code is (Theo)
  - flask-prototype-app/app/app.py - `/dashboard/*` routes and `role_required` decorator.
  - flask-prototype-app/app/templates/dashboard_*.html - dashboards per role.

- Steps
  - Log in as a `voter` -> `http://localhost:5000/dashboard` routes to the Voter dashboard.
  - Voter dashboard shows a red card (Eligibility Required) until a clerk approves; attempting `Secure Vote` redirects with guidance.
  - As voter, `/dashboard/admin` returns 403 and admin links are hidden.
  - Log in as `clerk` -> `dashboard/clerk` shows enrolment tools and a link to `Pending Approvals`.
  - Log in as `admin` -> `dashboard/admin` shows Operations and Access Control.

Eligibility Flow (Clerk Approvals)

- Purpose
  - Ensure voters can only vote after a clerk (or admin) verifies eligibility; prevent self-enrolment abuse.

- Steps
  - Voter registers and logs in → sees red “Eligibility Required” card on the Voter dashboard; `/secure/vote` is blocked.
  - Clerk logs in → visit `http://localhost:5000/clerk/approvals`.
  - Approve voter → voter becomes eligible (and a linked enrolled record is created/updated).
  - Voter logs in again → sees green “You are eligible” card and can vote via `/secure/vote`.
  - Deny removes the voter account (unless protected or it has recorded votes).

Backend RBAC Testing - Issue 8 (Theo)

- Purpose
  - Enforce role in API and store role in database (two separate requirements).

- Where the code is (Theo)
  - Database layer: `Role` table and `UserAccount.role` (FK) in `flask-prototype-app/app/app.py`.
  - API layer: `@role_required` applied to admin/clerk routes (e.g., `/add_candidate`, `/import_scanned`, `/audit/verify`, `/dashboard/admin`, `/admin/users`, `/admin/accounts`, `/clerk/approvals`).

- Steps
  - Create or log in as an admin user; visit `http://localhost:5000/admin/accounts` to create/delete users and change roles.
  - Change another user's role to `clerk` or `voter`; create a test voter account from `Admin Accounts`.
  - Confirm access:
    - `voter` cannot open `/add_candidate` or `/dashboard/admin` (403).
    - `clerk` can open `/clerk/approvals` and enrolment tools; cannot open admin pages.
    - `admin` can open `/dashboard/admin`, `/admin/accounts`, `/add_candidate`, `/import_scanned`, `/audit/verify`.
    - Then `docker compose up -d --build`
