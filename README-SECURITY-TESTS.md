Encryption Diagnostics - Issue 1 (Gurveen)

- Purpose
  - Validate that AES ballot confidentiality works and that the diagnostics UI is accessible for testing without login in demo mode.

- Where the code is (Gurveen)
  - flask-prototype-app/app/app.py:180 - global auth/MFA guard disabled for demo simplicity.
  - flask-prototype-app/app/app.py:781 - diagnostics route; no admin gate in demo mode.
  - flask-prototype-app/app/templates/index.html:47 - shows the diagnostics card when diagnostics flag is enabled.
  - flask-prototype-app/README.md - simplified, no-auth usage instructions.

- Setup
  - cd `flask-prototype-app`
  - `docker compose up --build`
  - Ensure `ENABLE_ENCRYPTION_DIAGNOSTICS=1` (entrypoint sets this automatically in Docker).

- Test (UI)
  1. Open `http://localhost:5000/home`.
  2. Cast a vote.
  3. Click the "Encryption Check" card to open diagnostics.
  4. Confirm the page shows a sample plaintext with AES-GCM ciphertext and the most recent stored ballot’s ciphertext with the server-side decrypted plaintext.

- Troubleshooting
  - If the card does not appear, verify the diagnostics flag is enabled.
  - For production, disable diagnostics (`ENABLE_ENCRYPTION_DIAGNOSTICS=0`) to hide the page.

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

- Vote with MFA enforced
  - Use `http://localhost:5000/secure/vote` to exercise the protected flow
  - Optional: enforce on original `/vote` by uncommenting `ENFORCE_MFA_ON_VOTE=true` in compose and `docker compose up -d`
  - Strict behavior when flag is ON (Theo):
    - You must be logged in.
    - If you have not set up MFA yet, you will be redirected to `/auth/mfa-setup` before voting.
    - If you have MFA set up but not yet verified this session, you will be redirected to `/auth/mfa`.

- Troubleshooting
  - If codes don't verify, check device time is accurate and retry within 30s window.
  - Ensure `SECRET_KEY` is set in compose so sessions persist.
  - Optional admin bootstrap for RBAC testing: set `BOOTSTRAP_ADMIN_USERNAME` and `BOOTSTRAP_ADMIN_PASSWORD` in compose, then `docker compose up -d`.

Frontend RBAC Testing - Issue 7 (Theo)

- Purpose
  - Verify separate dashboards and visibility based on role without JWT.

- Where the code is (Theo)
  - flask-prototype-app/app/app.py - `/dashboard/*` routes and `role_required` decorator.
  - flask-prototype-app/app/templates/dashboard_*.html - dashboards per role.

- Steps
  - Log in as a user with role `voter` -> `http://localhost:5000/dashboard` should route to the Voter dashboard.
  - As voter, you should not access `/dashboard/admin` (403) or see admin links.
  - Change user role to `clerk` (admin action below) and reload -> `dashboard/clerk` features appear; admin remains blocked.

Backend RBAC Testing - Issue 8 (Theo)

- Purpose
  - Enforce role in API and store role in database (two separate requirements).

- Where the code is (Theo)
  - Database layer: `Role` table and `UserAccount.role` (FK) in `flask-prototype-app/app/app.py`.
  - API layer: `@role_required` applied to admin/clerk routes (e.g., `/add_candidate`, `/import_scanned`, `/audit/verify`, `/dashboard/admin`, `/admin/users`).

- Steps
  - Create or log in as an admin user; visit `http://localhost:5000/admin/users`.
  - Change another user's role to `clerk` or `voter`.
  - Confirm access:
    - `voter` cannot open `/add_candidate` or `/dashboard/admin` (403).
    - `admin` can open `/dashboard/admin`, `/admin/users`, and `/add_candidate`.
  - To bootstrap an admin quickly, set env vars in compose:
    - `BOOTSTRAP_ADMIN_USERNAME=admin`
    - `BOOTSTRAP_ADMIN_PASSWORD=ChangeMe123456`
    - Then `docker compose up -d --build`
