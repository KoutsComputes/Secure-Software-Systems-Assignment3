# Electronic Voting Prototype

This repository contains a classroom prototype of an Australian federal election e-voting workflow. It demonstrates enrolment, candidate management, multiple voting flows (including overseas, above/below the line ballots), recount tooling, scanned ballot import, and a lightweight JSON results feed. Security controls are intentionally out of scope at this stage so the focus stays on the functional behaviour of the prototype.

## Project Layout

```
Secure-Software-Systems-Assignment3/
├─ app/
│  ├─ app.py           # Flask application: models, routes, tally logic
│  ├─ config.py        # Database configuration (SQLite by default)
│  ├─ models.py        # Legacy helpers (not required at runtime)
│  ├─ routes.py        # Legacy helpers (not required at runtime)
│  ├─ static/
│  │  └─ style.css
│  └─ templates/       # Jinja2 templates for each page described below
├─ requirements.txt
├─ Dockerfile
├─ docker-compose.yml  # Flask + MySQL 8 compose stack (host port 5001)
└─ README.md
```

## Prerequisites

- Python 3.9+ (only needed for running locally without Docker)
- Docker Desktop (tested on macOS ARM and Windows)
- Docker Compose v2 (`docker compose` command)

## Running the Prototype

### Option A: Docker Compose (recommended for consistent setup)

1. Ensure port `5001` on your host machine is free.
2. From the repository root, build and start the stack:
   ```bash
   docker compose down -v            # optional reset if you ran it before
   docker compose build --no-cache   # installs dependencies incl. cryptography
   docker compose up
   ```
3. Open http://localhost:5001 in your browser. The Flask container listens on port 5000 internally and is published to host port 5001 to avoid macOS Control Center using 5000.
4. Stop the stack with `Ctrl+C` in the terminal, or run `docker compose down` in another shell.

`docker-compose.yml` provisions:
- `web`: Flask app (`app/app.py`) with live code reload via a bind mount.
- `db`: MySQL 8.0 with credentials defined in the compose file. Data persists in the `secure-software-systems-assignment3_db_data` Docker volume.

### Option B: Local Python (SQLite by default)

1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. Launch the app:
   ```bash
   python app/app.py
   ```
3. Visit http://localhost:5000. The app will create `app/app.db` (SQLite).
4. To point at another database, set `DATABASE_URL`, e.g.:
   ```bash
   export DATABASE_URL="mysql+pymysql://user:password@localhost/flask_db"
   ```

## Usage Instructions

1. Launch the platform using either Docker Compose or local Python per the steps above.
2. Navigate to http://localhost:5001 (Docker) or http://localhost:5000 (local run). The landing page links every feature.
3. Set up enrolment data:
   - Register individual voters via **Register Voter** or allow them to self-enrol through **Self Enrol**.
   - Use **Update Address** to correct details and **Check Enrolment** to confirm status.
   - Review the current roll at **View Enrolled Voters**.
4. Populate candidates through **Add Candidate**. Provide party name and optional order number so ballot listings display correctly. Verify entries on **List Candidates**.
5. Collect electronic ballots:
   - Direct voters to **Standard Voting** for on-site ballots.
   - Provide mission-approved voters with **Overseas Voting** and their mission code.
6. Optionally ingest paper ballots in bulk under **Import Scanned Ballots** by pasting `house_prefs;senate_above;senate_below` lines.
7. Monitor results:
   - Open **Election Results** for live tallies and vote counts.
   - Run targeted exclusion scenarios through **Manual Recount** by listing candidate IDs.
   - Pull structured tallies from `GET /api/results` for downstream tools.
8. To reset demo data, clear the SQLite file (`app/app.db`) or run `docker compose down -v` when using MySQL.

## Working With the Prototype UI

The navigation bar (rendered from `app/templates/base.html`) links each feature. The following sections describe expectations and data captured by each flow.

### Landing Page

- Path: `/`
- Template: `index.html`
- Provides shortcuts to the major functional areas below.

### Voter Enrolment & Maintenance

- **Register Voter** (`/register_voter`): create a new voter with name/address and mark them enrolled. Persists to the `Voter` table.
- **Check Enrolment** (`/check_enrolment`): look up a voter by name and report `Enrolled`, `Not enrolled`, or `Not found`.
- **Self Enrol** (`/self_enrol`): allow an existing/unregistered voter to update details and mark themselves enrolled. Creates the voter if not already present.
- **Update Address** (`/update_address`): change the recorded address for an existing voter.
- **View Enrolled Voters** (`/voters`): list of currently enrolled voters sorted alphabetically.

### Candidate Management

- **Add Candidate** (`/add_candidate`): record candidate name, party, and optional ticket order number. Inserts into the `Candidate` table.
- **List Candidates** (`/candidates`): grouped/sorted display of all candidates for reference while voting.

### Voting Flows

- **Standard Voting** (`/vote`):
  - Requires the voter to be enrolled; prevents duplicate votes by checking existing `Vote` records.
  - Captures:
    - `house_preferences`: comma-separated candidate IDs for House of Representatives.
    - `senate_above`: comma-separated party names entered above the line.
    - `senate_below`: comma-separated candidate IDs entered below the line.
- **Overseas Voting** (`/vote_overseas`):
  - Same payload as `/vote` but gated by an `ALLOWED_MISSIONS` mission code list (`app.py`).
  - Mission codes currently accepted: `AUS-LONDON`, `AUS-WASHINGTON`, `AUS-TOKYO`, `AUS-SINGAPORE`.
  - Validates enrolment and prevents double-voting just like the standard form.

Votes are stored in the `Vote` table with `source="electronic"`. Basic validation ensures a voter only submits once.

### Results & Analysis

- **Election Results** (`/results`):
  - Aggregates House first-preference tallies, Senate party tallies (each party entry counts as one), and Senate below-the-line first preferences.
  - Displays candidate names when IDs match known candidates. Includes a total vote count.
- **Manual Recount** (`/recount`):
  - Accepts a comma-separated list of candidate IDs to exclude from House/Senate tallies, simulating eliminations.
  - Recalculates first-preference results ignoring those IDs.
- **Scanned Ballot Import** (`/import_scanned`):
  - Accepts semi-colon (`;`) separated lines in the format `house_prefs;senate_above;senate_below`.
  - Each line becomes a new `Vote` with `voter_id=0` and `source="scanned"`.
  - After import, redirects to `/results`.
- **JSON Results API** (`/api/results`):
  - Returns a JSON object mirroring the `/results` tallies for external systems.
  - Example response:
    ```json
    {
      "house_first_pref_tally": {"1": 5, "2": 3},
      "senate_party_tally": {"Party A": 4, "Party B": 2},
      "senate_candidate_first_pref_tally": {"1": 3, "5": 1},
      "total_votes": 7
    }
    ```

## Database Notes

- Default SQLite database file is `app/app.db`. Remove it to reset local data.
- When running with Docker Compose, MySQL credentials are:
  - Database: `flask_db`
  - User: `user`
  - Password: `password`
  - Root password: `root_password`
- The Flask app connects through `DATABASE_URL=mysql+pymysql://user:password@db/flask_db` configured in `docker-compose.yml`.

## Troubleshooting

- **Port already in use**: On macOS ARM, the Control Center can bind port 5000. The compose file maps the app to host port 5001 to avoid this. Adjust or reclaim port 5000 via System Settings ▸ General ▸ AirDrop & Handoff ▸ AirPlay Receiver if you prefer the original port.
- **MySQL driver error (`cryptography` required)**: The dependency is listed in `requirements.txt`. Rebuild the Docker image (`docker compose build --no-cache`) after modifying requirements.
- **Resetting state**: `docker compose down -v` removes containers and the MySQL volume for a clean start. For SQLite, delete `app/app.db`.

## Known Limitations

- No authentication, authorisation, or security hardening is implemented yet.
- Vote validation is intentionally simplistic; full preferential counting and audit trails are not covered.
- Administrative routes are exposed without protections because security requirements are explicitly deferred for now.

## Contributing / Extending

- Add new routes or templates under `app/`.
- Update the database models in `app/app.py` (remember to rebuild or run migrations if you add columns in a real deployment).
- Always rebuild the Docker image after changing dependencies.

Feel free to tailor the workflows or extend the data model to suit further experimentation—you now have a baseline, security-free voting prototype running on macOS, Windows, and Linux via Docker.
