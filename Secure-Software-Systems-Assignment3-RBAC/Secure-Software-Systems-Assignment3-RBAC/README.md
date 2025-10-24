# Electronic Voting Prototype

A demonstration prototype for an Australian federal election e-voting system. This project showcases the essential components of a secure, user-friendly electronic voting platform.

---

## Table of Contents

- [Overview](#overview)
- [Default Branch](#default-branch)
- [Features](#features)
- [Project Structure](#project-structure)
- [Setup Instructions](#setup-instructions)
  - [Local Setup (SQLite)](#local-setup-sqlite)
  - [Docker Setup (MySQL)](#docker-setup-mysql)
- [Usage Guide](#usage-guide)
- [API Reference](#api-reference)
- [Security Requirements](#security-requirements)
- [Limitations & Notes](#limitations--notes)
- [Credits](#credits)

---

## Overview

The app simulates the core workflow of an Australian federal election, including voter enrolment, candidate management, voting for both the House of Representatives and the Senate (Above The Line and Below The Line), results tallying, scanned ballot import, and a public results API. The system is built using Flask and is intended for demonstration and learning, not for production use.

---

## Default Branch

This repository uses `master` as the primary branch (instead of `main`). If your Git tooling defaults to `main`, switch to `master` to see the latest work:

- `git checkout master`
- Or browse the `master` branch on GitHub.

## Features

- **Voter Enrolment:** Register, check status, self-enrol, and update address.
- **Candidate Management:** Add candidates, manage party groups, and view candidate lists.
- **Voting:** 
  - House: Preference voting (comma-separated).
  - Senate: Above The Line (party names) and Below The Line (candidate IDs).
- **Overseas Voting:** Access controlled by mission codes (demo list).
- **Results:** First-preference tallies, manual recount with exclusions.
- **Scanned Ballots:** Import via CSV-like paste.
- **API:** `GET /api/results` returns JSON tallies for House and Senate.

---

## Project Structure

```
Secure-Software-Systems-Assignment3/
|-- app/
|  |-- app.py               # Main application, models & routes
|  |-- config.py            # Database configuration (SQLite/MySQL)
|  |-- static/style.css     # Stylesheet
|  `-- templates/           # HTML templates
|     |-- index.html
|     |-- register_voter.html
|     |-- check_enrolment.html
|     |-- self_enrol.html
|     |-- update_address.html
|     |-- add_candidate.html
|     |-- candidates.html
|     |-- vote.html
|     |-- vote_overseas.html
|     |-- results.html
|     |-- recount.html
|     `-- import_scanned.html
|-- requirements.txt        # Python dependencies
|-- Dockerfile              # Container build
|-- docker-compose.yml      # Multi-container setup
`-- README.md               # Project info
```

---

## Setup Instructions

### Local Setup (SQLite)

1. **Clone the repository:**
   ```
   git clone <repo-url>
   cd Secure-Software-Systems-Assignment3
   ```

2. **Create a virtual environment:**
   ```
   python -m venv venv
   venv\Scripts\activate   # On Windows
   ```

3. **Install dependencies:**
   ```
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```
   python app/app.py
   ```

5. **Access the app:**
   Open [http://localhost:5000](http://localhost:5000) in your browser.

---

### Docker Setup (MySQL)

1. **Build and start containers:**
   ```
   docker-compose up --build
   ```

2. **Access the app:**
   Open [http://localhost:5000](http://localhost:5000).

**Notes:**
- Live code reload: The `./app` directory is mounted into the container. Changes reflect on refresh.
- To use SQLite in Docker, remove `DATABASE_URL` from `docker-compose.yml` and the `db` service.

---

## Usage Guide

- **Enrolment:** Register as a voter, check your enrolment status, or update your address.
- **Candidate Management:** Add new candidates and manage party groupings.
- **Voting:** Cast votes for House and Senate (choose ATL or BTL).
- **Overseas Voting:** Enter a valid mission code to access overseas voting.
- **Results:** View live tallies and perform manual recounts.
- **Import Scanned Ballots:** Paste CSV-like data to include scanned ballots in results.

---

## API Reference

- **Results API:**  
  `GET /api/results`  
  Returns JSON-formatted tallies for House and Senate.

---

## Security Requirements

High-level descriptions of security requirements and where they are implemented. See `README-SECURITY-TESTS.md` for verification steps.

- 1. Voter Confidentiality (AES-GCM at rest)
  - Encrypts ballot fields before storage.
  - Files: `flask-prototype-app/app/crypto_utils.py`, used in `app/app.py` vote handlers.
- 2. Vote Integrity (TLS/HSTS)
  - HTTPS redirect + HSTS when TLS is enabled; dev self-signed support.
  - Files: `flask-prototype-app/app/app.py`, `flask-prototype-app/app/config.py`.
- 3. Availability and DDoS Resilience
  - Per-IP rate limiting with shared backend across replicas (Redis).
  - Files: `flask-prototype-app/app/app.py`, `flask-prototype-app/docker-compose.yml`.
- 4. Non‑Repudiation (Digital Signatures)
  - Append-only audit log with HMAC chain and Ed25519 signatures.
  - Files: `flask-prototype-app/app/security.py`.
- 5. Incident Response and Recovery
  - Container health checks, restart policy, ordered dependencies.
  - Files: `flask-prototype-app/docker-compose.yml`.
- 6. Voter Authentication (Password + MFA)
  - Password hashing, TOTP MFA, MFA-gated vote route.
  - Files: `flask-prototype-app/app/app.py`, `app/templates/auth_*`.
- 7. RBAC (Frontend)
  - Separate dashboards per role.
  - Files: `flask-prototype-app/app/app.py`, `app/templates/dashboard_*.html`.
- 8. RBAC (Backend)
  - DB-stored role + API decorator `@role_required`.
  - Files: `flask-prototype-app/app/app.py`.
- 9. Tamper‑Free Logging
  - Append-only records with verifiable chain and signatures.
  - Files: `flask-prototype-app/app/security.py`.
- 10. Vote Verifiability (Receipt)
  - Metadata-based HMAC receipt; verify via `/verify`.
  - Files: `flask-prototype-app/app/app.py` (`_generate_receipt`).
- 11. Automatic Backups (DB Replication)
  - MySQL primary with replica.
  - Files: `flask-prototype-app/docker-compose.yml`, `flask-prototype-app/mysql/*`.
- 12. Geolocation Restrictions
  - CF-IPCountry allowlist.
  - Files: `flask-prototype-app/app/security.py`.
- 13. API Rate Limiting (No nginx)
  - Flask-Limiter with Redis storage.
  - Files: `flask-prototype-app/app/app.py`.
- 14. Caching Common Data
  - In-memory TTL cache + Cache-Control headers.
  - Files: `flask-prototype-app/app/app.py`.
- 15. Session Recovery
  - LocalStorage persistence for vote forms.
  - Files: `flask-prototype-app/app/templates/vote*.html`.
- 16. Input Validation
  - Server-side sanitizers for CSV inputs; ORM queries.
  - Files: `flask-prototype-app/app/app.py`.
- 17. Saved Backups (Hybrid)
  - Admin endpoint writes JSON backups to local and simulated cloud dirs.
  - Files: `flask-prototype-app/app/app.py`, `flask-prototype-app/app/config.py`.
- 18. Minimal Downtime (2 instances)
  - Two Flask replicas behind HAProxy with health checks.
  - Files: `flask-prototype-app/docker-compose.yml`, `flask-prototype-app/haproxy/haproxy.cfg`.
- 19. HTTPS/TLS Everywhere
  - TLS/HSTS in app; docs for HAProxy TLS termination.
  - Files: `flask-prototype-app/app/app.py`, `README-SECURITY-TESTS.md`.
- 20. URL Validation
  - Whitelist/relative URL checks and admin tester endpoint.
  - Files: `flask-prototype-app/app/app.py`.

---

## Limitations & Notes

- This is a minimal prototype for demonstration and educational purposes.
- For any issues or suggestions, please open an issue or contact the maintainers.

---

## Credits
Developed for RMIT Secure Software Systems Assignment 3.

---
