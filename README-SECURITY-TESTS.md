Security Testing Guide — Incident Recovery (Issue 5)

- Purpose
  - Test Docker health status, ordered startup, and auto‑restart using a single Compose‑based solution.

- Where the code is (Theo)
  - flask-prototype-app/app/app.py:58 — adds `/healthz` endpoint.
  - flask-prototype-app/docker-compose.yml:15 — web restart policy + healthcheck + depends_on (healthy DB).
  - flask-prototype-app/docker-compose.yml:42 — db healthcheck.
  - flask-prototype-app/docker-compose.yml:67 — replica depends_on + healthcheck.

- Requirements
  - Docker Desktop or Docker Engine with Compose v2.
  - PowerShell (Windows) or curl.

- Test (flask-prototype-app only)
  - cd `flask-prototype-app`
  - Bring up: `docker compose up -d --force-recreate`
  - Check health:
    - PowerShell: `Invoke-RestMethod http://localhost:5000/healthz`
    - curl: `curl http://localhost:5000/healthz`
  - Auto‑restart (web):
    - `docker compose exec web sh -c "kill 1"`
    - `docker compose ps` (web should return to “Up”)
    - Restart count (PowerShell):
      - `$id = (docker compose ps -q web)`
      - `docker inspect -f "{{ .RestartCount }}" $id`
  - Ordered startup (db → web):
    - `docker compose down`
    - `docker compose up -d`
    - `docker compose ps` (db becomes healthy first, then web shows healthy)

- Troubleshooting
  - Port 3306 already in use: stop other stacks using MySQL or change/remove the db `ports:` mapping.
  - Healthcheck failing does not restart by itself; restarts happen on process exit or Docker daemon restart.
  - If `depends_on: condition: service_healthy` is ignored, update Docker Compose to v2.
