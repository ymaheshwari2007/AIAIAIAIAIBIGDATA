# CLAUDE.md

Project context for Claude Code. Read this before doing anything in this repo.

Every decision recorded here was made by the owners. Do not add, swap, or "improve" any tool, library, port, or convention on your own. If something isn't covered here, it is an OPEN decision: propose options and wait for the owners to choose. See the Decision Log.

---

## HARD RULE: explain before you touch anything

Before creating or editing ANY file, first say, in plain language, what the change does and why. Then make it. No silent edits, ever, no matter how small. One combined explanation for a batch of related edits is fine, but nothing gets written that the owners didn't see explained first.

This exists because the owners make every decision on this project. If you catch yourself about to write a choice into a file that the owners didn't explicitly make, stop and ask instead.

---

## What this project is

DepWatch is a small vulnerability intelligence platform. It ingests public security advisories every day, indexes them for semantic search, and uses an LLM agent to tell us which dependencies in our own projects are actually dangerous, whether we're realistically affected, and how long a finding has been open. Grafana monitors both the pipeline and the security posture over time.

Think "scoped-down Snyk, built to learn the architecture." It is not a product, it has no customers, and it does not need to scale.

---

## Learning project: how to work here

Two rising sophomores are building this to learn data engineering and applied AI. If you write all the code, the project fails at its purpose even if the code works.

- Explain the approach and the tradeoffs BEFORE writing code, and wait for a go-ahead on anything non-trivial.
- Prefer scaffolding over finished implementations: correct structure, clear function signatures, docstrings, and `TODO` markers for the interesting logic. Let us fill in the core logic.
- When you write a full implementation (fine for config, Dockerfiles, glue), explain the parts new to us, especially anything Airflow-, SQLAlchemy-, Alembic-, pgvector-, or Prometheus-specific.
- When there are several reasonable ways to do something, present them with a recommendation and reason. Do not silently pick one. The owners make the call.
- If we ask for a bad idea, say so directly.

Full autonomous implementation is fine for: config files, Docker/compose setup, test fixtures, type hints, docstrings, refactors we ask for, and debugging errors we're stuck on. Even then, the HARD RULE above applies: explain first.

Stop and ask before: schema changes, adding any new dependency/service/tool, changing the agent's prompt strategy, deciding anything marked OPEN or DEFERRED below, and anything touching more than ~3 files.

---

## Decision Log

Everything here was chosen by the owners. This is the source of truth.

**DECIDED:**
- Project: DepWatch, a vulnerability intelligence tool
- Language: Python
- Orchestration: Apache Airflow 3.x
- Executor: LocalExecutor (tasks run in the scheduler; no Redis, no separate worker)
- Database: two Postgres containers — `postgres` (Airflow metadata) and `appdb` (our `depwatch` app data, on host port `5433` since `5432` is often taken by a local Postgres). Kept separate so resetting our schema never disturbs Airflow.
- Postgres images: app DB (`appdb`) on `pgvector/pgvector:pg16` (vector extension available, switched on at Stage 3); Airflow metadata on plain `postgres:16`
- Vector store: pgvector, inside the `depwatch` database (not a separate vector DB)
- DB access layer: SQLAlchemy 2.0 ORM (declarative models); idempotent writes use Core-style `insert().on_conflict_do_update()`
- Migrations: Alembic
- Raw storage: MinIO (S3-compatible object storage), the raw landing zone for untouched API responses
- Secrets: API tokens (e.g. `GITHUB_TOKEN` for the GHSA API) live in `.env` env vars, not Airflow connections; the Fernet key stays deferred until we need encrypted connection storage
- Airflow UI port: 8080 (default)
- Data sources: GitHub Security Advisories (GHSA) + OSV.dev as primary, NVD as enrichment
- Observability tools: Prometheus + Grafana (specific dashboards/metrics deferred, see below)
- Trivy: validation benchmark and container scanner ONLY, never the matching engine
- Packaging: Docker Compose, built up incrementally (add a service only when the current stage needs it)

**OPEN (not yet decided, ask the owners before acting):**
- Nothing outstanding right now. If a new fork appears, it lands here until the owners decide.

**DEFERRED (decide when we reach the stage, not before):**
- Embedding model (Stage 3): local free model vs paid API
- Agent framework (Stage 4): raw SDK loop vs a framework like LangGraph
- Database schema (Stage 2): the owners drive the design
- Which metrics and dashboards (Stage 5)

---

## Architecture

```
  sources              ingest            store              index            reason            observe
  GHSA API      ->                ->     MinIO (raw)
  OSV.dev dump  ->     Airflow           Postgres     ->    pgvector    ->   LLM agent   ->    Grafana
  NVD API       ->     DAGs        ->    (depwatch db)      index            + memory          Prometheus
                                                                                 |                ^
                                                                                 +-- findings ----+
```

Airflow DAGs pull advisories daily, land raw JSON in MinIO and normalized rows in Postgres (via SQLAlchemy ORM), embed advisory text into pgvector, then the agent takes a project's dependency file, retrieves relevant advisories, reasons about real impact, and writes findings plus per-project memory back to Postgres. Everything emits Prometheus metrics that Grafana renders.

---

## Repo structure

```
depwatch/
|-- docker-compose.yaml       # grows over time; only services the current stage uses
|-- Dockerfile                # custom Airflow image (added at Stage 1 when DAGs need our libs)
|-- .env.example              # every env var with fake values. NEVER commit .env
|-- alembic/                  # Alembic migration environment + versions
|-- alembic.ini
|-- dags/                     # Airflow DAGs, thin orchestration only
|-- depwatch/                 # the importable, testable library
|   |-- config.py             # all env vars read once, here
|   |-- sources/              # one client per data source
|   |-- transform/            # normalization + multi-source merge
|   |-- storage/              # Postgres (SQLAlchemy ORM) + MinIO access
|   |-- embedding/            # embedding + vector search (Stage 3)
|   |-- agent/                # retrieval, prompts, triage loop, memory (Stage 4)
|   +-- metrics/              # Prometheus instrumentation (Stage 5)
|-- monitoring/               # prometheus.yml, grafana dashboards (Stage 5)
|-- tests/
+-- projects/                 # dependency files of the repos we watch
```

Thin DAGs: a DAG file wires tasks together and schedules them. All real logic lives in `depwatch/` so it can be unit-tested without spinning up Airflow. If a DAG file is accumulating real logic, it belongs in the library instead.

---

## Docker Compose: build it up, don't front-load it

Add each service only when the stage that uses it arrives.

- Stage 0/1: two Postgres containers (`postgres` metadata + `appdb` on pgvector) and the Airflow 3.x LocalExecutor services (api-server, scheduler, dag-processor, triggerer, init). No Redis, no worker, no Flower.
- MinIO: ✅ added at Stage 1 for raw JSON landing. Console at `localhost:9001`.
- Prometheus + Grafana: added at Stage 5.

---

## Data sources (verified, use these exact facts)

**GitHub Security Advisories, primary.** `GET https://api.github.com/advisories` with `Accept: application/vnd.github+json`. 60 req/hour unauthenticated, 5000 with a free token. Paginate via the `Link` header. Gives `ghsa_id`, `cve_id`, `severity`, `summary`, `description`, and `vulnerabilities[]` with ecosystem, package name, vulnerable range, and first patched version. Use `ghsa_id` as `source_id`, `source = 'github'`.

**OSV.dev, primary.** Bulk zip dumps at `https://storage.googleapis.com/osv-vulnerabilities/{ECOSYSTEM}/all.zip` (e.g. `PyPI`, `npm`, `Go`, `Maven`), refreshed daily. Prefer the bulk zips over the query API since a file can't rate-limit you. Use OSV's `id` as `source_id`, `source = 'osv'`.

**NVD, enrichment only.** `https://services.nvd.nist.gov/rest/json/cves/2.0`. Free API key. Limits: 5 requests / 30s without a key, 50 with one, so sleep between requests. Use `lastModStartDate` / `lastModEndDate` for incremental syncs. Use the CVE id as `source_id`, `source = 'nvd'`. NVD is keyed by CPE strings, which are painful to match against a package.json, which is why it's enrichment (CVSS scores, extra references), not primary.

**Never fabricate advisory data.** For test data, use a real record or clearly name the fixture `FAKE_ADVISORY_FOR_TESTS`.

---

## Ingestion must be idempotent

Re-running any pull must never duplicate rows. Airflow retries tasks, incremental pulls overlap at the edges, and we trigger DAGs by hand constantly, so every advisory can arrive many times.

- Every advisory row's identity is the pair `(source, source_id)`, with a UNIQUE constraint on that pair.
- Writes are upserts: `INSERT ... ON CONFLICT (source, source_id) DO UPDATE SET <mutable fields>, updated_at = now()`. Use the Postgres-specific `insert(...).on_conflict_do_update(...)` — it works against ORM models in SQLAlchemy 2.0.
- The pair, not the bare id, is the key on purpose: the same CVE appears in GHSA, OSV, and NVD, and keying on `source_id` alone would make those copies overwrite each other. Keeping `source` in the key lets each source hold its own row, which the merge step reconciles later.
- Keep `created_at` fixed on update; only refresh `updated_at` and the mutable fields.

---

## Trivy: benchmark, not engine

Trivy is a validation baseline and container scanner ONLY. Building our own ingestion and matching is the point of Stages 1 and 3.

- Run `trivy fs` on a watched repo and diff its findings against ours: this is our eval harness.
- Run `trivy image` on our own service images for container-layer coverage.
- Later (Stage 4+) it may feed the agent as a second signal.

If you're ever about to suggest "just call Trivy here" in place of our own retrieval or matching, stop and flag it.

---

## Database conventions

- Plural snake_case table names: `advisories`, `projects`, `dependencies`, `findings`, `agent_memory`, `raw_ingest_log`.
- Every table gets `created_at timestamptz default now()`, and `updated_at` where mutable.
- Advisories carry `source` and `source_id` with a UNIQUE constraint on the pair (see idempotency above). A plain auto-increment `id` can serve as the primary key alongside it.
- Schema changes go through Alembic migrations. Do not hardcode the pgvector embedding dimension until we pick the embedding model at Stage 3.
- The schema itself is the owners' to design (Stage 2). Propose and advise; do not finalize tables on your own.

## Airflow conventions

- Every DAG idempotent. Re-running any task must not duplicate rows (upsert on `(source, source_id)`).
- Incremental by default using a last-successful-run watermark. Full refresh only as a separate, explicitly triggered DAG.
- `retries` and `retry_delay` on every network task; these APIs are flaky and handling that is a feature.
- Tasks log counts (fetched, inserted, updated, skipped) and export them as Prometheus metrics (Stage 5).
- No secrets in DAG code; use env vars or Airflow connections.

## Code conventions

- Type hints on all signatures. `ruff` for lint + format.
- Small pure functions in `transform/`, tested with plain pytest; no test should need Docker.
- Config via env vars, read once in `depwatch/config.py`.
- Comments explain why, not what.

---

## Commands

```bash
docker compose up airflow-init      # first-time: run migrations + create the airflow/airflow login
docker compose up -d                # bring up whatever services exist so far
docker compose logs -f airflow-scheduler
alembic revision --autogenerate -m "message"   # create a migration
alembic upgrade head                # apply migrations to the depwatch db
pytest                              # tests
ruff check . && ruff format .       # lint + format
trivy fs projects/impacttrail       # baseline scan for comparison
```

Airflow UI at `localhost:8080` (login `airflow` / `airflow`). Grafana at `localhost:3000` and MinIO console at `localhost:9001` once those services exist.

---

## Roadmap

Grouped as three phases across six stages. **Currently: Phase 1.**

**Phase 1, data spine (Stages 0-2). CURRENT.**
- Stage 0 — ✅ **done**: two-Postgres + Airflow LocalExecutor compose, `depwatch/config.py`, a hello-world DAG running green (`dags/hellow_world.py`), Alembic wired to `appdb`.
- Stage 1 — 🔨 **in progress**: GHSA advisories → raw JSON landed in MinIO **works** (`depwatch/sources/ghsa.py` fetch/paginate + `ingest_raw`, using `depwatch/storage/minio.py`; HTTP via `requests`; raw objects keyed `github/dt=<ingest-date>/advisories_p<n>.json`). Remaining: the Airflow DAG that runs it daily, then OSV, NVD, and normalized rows in Postgres. Done when fresh advisories land daily unattended and reruns never duplicate.
- Stage 2: design the Postgres schema (the owners drive) — from the raw advisories we've now landed.

**Phase 2, AI layer (Stages 3-4).**
- Stage 3: pick the embedding model, embed into pgvector, build metadata-filtered retrieval (filter by ecosystem/package, then vector rank).
- Stage 4: pick the agent framework, build the triage loop, structured findings, per-project memory. Done when pointing it at one of our repos gives a report that makes sense.

**Phase 3, observability (Stage 5).**
- Prometheus instrumentation everywhere, Grafana dashboards. The owners pick the metrics. Done when one dashboard shows the whole system alive.

**Stage 6, validation.** Trivy diff harness + container scanning, once there are findings to compare.

Do not build ahead of the current stage. Flag later ideas instead of building them. Scope creep is the most likely way this project dies.

---

## Watched projects

`projects/` holds the dependency files of the repos DepWatch monitors. First targets: ImpactTrail and Rainfall. Get ImpactTrail working end to end first, then add Rainfall.

## Non-goals

- No multi-tenant, auth, or user accounts.
- Not real time; daily is fine and matches the sources.
- Not big data by volume; we practice the patterns (idempotency, raw vs. curated, partitioning) at small scale on purpose.
- Not trying to beat Dependabot or Snyk; prior art existing means the problem is real.

## Definition of done for any task

1. It runs.
2. It's idempotent if it writes data.
3. It has a test if it contains logic.
4. It emits a metric if it's a pipeline step (from Stage 5 on).
5. Both of us could explain the design choice in an interview without hand-waving.