# DepWatch

A small vulnerability-intelligence platform we're building to learn data engineering and applied AI. It ingests public security advisories, indexes them, and (later) uses an LLM agent to flag which of our own dependencies are actually at risk.

It's built in stages. **Right now it's at Stage 0:** the data spine is stood up — Airflow orchestration on top of Postgres. No pipelines yet, just the plumbing running green.

## What's running

- **Apache Airflow 3.3.0** (LocalExecutor) — api-server, scheduler, dag-processor, triggerer
- **Two Postgres containers:**
  - `postgres` (Postgres 16) — Airflow's own metadata
  - `appdb` (Postgres 16 + pgvector) — our application data, the `depwatch` database (empty for now)

MinIO, Prometheus, and Grafana arrive in later stages.

## Prerequisites

- **Docker Desktop**, with at least **4 GB of RAM** allocated (Settings → Resources).
- Nothing else — everything runs in containers.

## Get it running

```bash
git clone <repo-url>
cd AIAIAIAIAIBIGDATA

cp .env.example .env              # local config, safe defaults (this file is gitignored)

docker compose up airflow-init    # one-off: pulls images, migrates the db, creates the login.
                                  # Wait for "airflow-init-1 exited with code 0".

docker compose up -d              # start everything
docker compose ps                 # every service should read "healthy"
```

The first run pulls a few hundred MB of images, so give it a few minutes.

## Use it

- **Airflow UI** (a web page) → open <http://localhost:8080> in a browser, log in with `airflow` / `airflow`.
  It's empty of DAGs on purpose (Airflow's examples are turned off) — that's expected at Stage 0.
- **App database** (not a web page — a browser can't open it) → connect a Postgres client
  (`psql`, [DBeaver](https://dbeaver.io), or a VS Code SQL extension) with:
  host `localhost`, port `5433`, database `depwatch`, user `depwatch`, password `root`.
  (Port 5433, not 5432, so it doesn't collide with a Postgres you may already run locally.)
  Fastest, no install: `docker compose exec appdb psql -U depwatch -d depwatch`.

## Everyday commands

```bash
docker compose ps                        # status
docker compose logs -f airflow-scheduler # tail one service
docker compose down                      # stop everything, KEEP the data
docker compose down -v                   # stop AND wipe the database volume (full reset)
```

`down` keeps your databases in a Docker volume, so `up -d` next time picks up where you left off. Use `-v` only for a clean slate — it deletes the Postgres data; `appdb` then comes back with an empty `depwatch` database, and you re-run migrations (below) to rebuild the schema.

## Local development (migrations)

Alembic — our schema-migration tool — runs on **your machine**, not in a container, so it needs a Python environment. One-time setup:

```bash
python3.13 -m venv .venv          # 3.13 to match the Airflow image
source .venv/bin/activate
pip install -r requirements.txt
```

Then, with `appdb` running (Alembic reaches it at `localhost:5433`):

```bash
alembic upgrade head               # apply all migrations
alembic revision -m "add findings" # start a new migration, then edit the generated file
alembic downgrade -1               # roll back one
alembic current                    # what's applied right now
```

Run these from the repo root, so `alembic/env.py` can import `depwatch.config` and read `.env`. There are no app tables yet — the schema gets designed at Stage 2.

## Layout

```text
docker-compose.yaml     the whole stack
dags/                   Airflow DAGs (thin orchestration only)
depwatch/               the importable library (the real logic lives here)
alembic/                database migrations (+ alembic.ini at the root)
requirements.txt        host-side Python deps (Alembic, SQLAlchemy, ...)
.env.example            copy to .env
```

Credentials here are all throwaway local-dev values — fine for a laptop, not for anything real.