<<<<<<< HEAD
# Secure-Software-Systems-Assignment3

hey guys
=======
# Electronic Voting Prototype (Flask)

Basic working prototype for an Australian federal election e-voting system covering the functional requirements: enrolment, candidate management, voting for House and Senate (ATL/BTL), simple results, import of scanned ballots, and a JSON results API.

## Project Structure

```
flask-prototype-app
├─ app
│  ├─ app.py               # main app, models + routes
│  ├─ config.py            # defaults to SQLite, supports DATABASE_URL
│  ├─ static/style.css
│  └─ templates/
│     ├─ index.html
│     ├─ register_voter.html
│     ├─ check_enrolment.html
│     ├─ self_enrol.html
│     ├─ update_address.html
│     ├─ add_candidate.html
│     ├─ candidates.html
│     ├─ vote.html
│     ├─ vote_overseas.html
│     ├─ results.html
│     ├─ recount.html
│     └─ import_scanned.html
├─ requirements.txt
├─ Dockerfile
├─ docker-compose.yml
└─ README.md
```

## Setup

1) Create a virtualenv and install dependencies:

```
pip install -r requirements.txt
```

2) Run the app (SQLite by default):

```
python app/app.py
```

Open http://localhost:5000

Optionally, set `DATABASE_URL` to point at MySQL if using Docker compose.

## Run with Docker Compose

MySQL is provisioned via docker-compose. The app is auto-configured using `DATABASE_URL` with PyMySQL.

Commands:

```
docker-compose up --build
```

Then open http://localhost:5000

Notes:
- Live code reload: the `./app` directory is mounted into the container. Edits reflect immediately on refresh.
- If you prefer SQLite instead of MySQL in Docker, remove `DATABASE_URL` from `docker-compose.yml` and the `db` service; the app will fall back to SQLite.

## Features in this prototype

- Voter enrolment: register, check status, self-enrol, update address
- Candidate management: add candidates, order within party groups, list view
- Voting: House preferences (comma-separated), Senate ATL (party names) and BTL (candidate IDs)
- Overseas voting: gated by mission codes (prototype list)
- Results: simple first-preference tallies; recount with manual exclusions
- Scanned ballots: import via CSV-like paste to include in results
- API: `GET /api/results` returns JSON tallies

## Notes

- This is a minimal prototype. Real electoral counting (preferential/STV) and security hardening are out of scope.
- Admin/RBAC/MFA are not implemented; pages are open for demonstration.
>>>>>>> ed8081e (Initial commit of submodule)
