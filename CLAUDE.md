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

Think "scoped-down Snyk, built for real." We're building toward a production-grade, likely hosted and multi-tenant service, and we architect with that in mind — while still building in stages, core engine first. It's also how the two of us learn data engineering and applied AI.

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

**Default to plan mode; never edit in edit-only mode by default.** Start every task by planning. Do not make file edits or run state-changing commands (writes, installs, downloads, `docker`, migrations) until a plan is presented and the owners approve it. Leave plan mode / make changes only when the owners explicitly say to proceed — and only for what the approved plan covers. "Explain first" is the floor; plan-first-then-approve is the default.

---

## Decision Log

Everything here was chosen by the owners. This is the source of truth.

**DECIDED:**
- Project: DepWatch, a vulnerability intelligence tool
- Language: Python
- Orchestration: Apache Airflow 3.x
- Executor: LocalExecutor (tasks run in the scheduler; no Redis, no separate worker)
- Database: two Postgres containers — `postgres` (Airflow metadata) and `appdb` (our `depwatch` app data, on host port `5433` since `5432` is often taken by a local Postgres). Kept separate so resetting our schema never disturbs Airflow.
- Postgres images: app DB (`appdb`) on `pgvector/pgvector:pg16` (vector extension enabled at Stage 3 — `advisories.embedding` is live); Airflow metadata on plain `postgres:16`
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
- App schema (Stage 2): two tables — `advisories` (one row per `(source, source_id)`) and `affected` (child, one row per package × version range, FK to advisories with `ON DELETE CASCADE`). Package identity (`ecosystem` + `package_name`) lives as columns on `affected`, NOT a separate `packages` table (promote to a 3-table many-to-many later only if needed). `cwes` is a `text[]` array column; `cve_id` is a single nullable column. Cross-source dedup is a MERGE-step concern, not ingest — both GHSA and OSV rows are kept (that's why the key is the pair). Provenance trimmed to a single `url`. No pgvector column yet (Stage 3). Diagram in the README "Schema" section; models in `depwatch/storage/postgres.py`.
- Embedding model (Stage 3, DECIDED): Qwen3-Embedding-0.6B — local, free, Apache-2.0, 1024-dim. Chosen over paid APIs (OpenAI etc.) and heavier models (NV-Embed-v2, bge) to stay local, free, and laptop-friendly (runs on the Mac GPU in seconds). Advisory `summary + description` is embedded into an `advisories.embedding` `Vector(1024)` column; `embedded_at` drives incremental re-embedding. Retrieval is filter-then-rank (SQL package filter on `affected` → vector cosine rank) with an HNSW index. Code in `depwatch/embedding/`.
- Embedding runtime (Stage 3, DECIDED): "Route B" — embeddings run on the Mac's GPU (Metal/MPS) via a small host-side FastAPI launcher (`depwatch/embedding/service.py`), NOT inside Docker (containers can't reach the Mac GPU). The Airflow `embed` task POSTs to it; the launcher spawns a run-and-exit subprocess so the model only occupies RAM during a run. Kept alive by a macOS launchd LaunchAgent.
- Agent design (Stage 4, AGREED — both owners): (1) **local agent first, hosted multi-tenant later** — the hosted "submit your repo" service is now an agreed target (see "Production target"), still sequenced after the core engine works; (2) **deterministic matching in code** (version-range checks + retrieval), **LLM only for judgment** ("given how it's used, are we really affected?") — keeps cost/latency low; (3) **provider-agnostic `reason()` interface + BYO-key**, default **Gemini 3 Flash free tier**, swappable to GitHub Models / Groq / Claude / GPT via `.env`; (4) entry point = **paste a repo URL → shallow read-only clone → extract deps → parse**. NEVER execute code from a scanned repo. Built in sub-stages 4a–4d.
- Dependency extraction (Stage 4, DECIDED): **OSV-SCALIBR** (Google's `scalibr` CLI), chosen after research over Syft / dparse / cdxgen for tightest OSV alignment (our vuln data is OSV/GHSA), polyglot coverage, and extraction-only focus. Emits SPDX v2.3 JSON with PURLs; we parse those and normalize to our `affected.ecosystem` spelling. CPU-only binary (no GPU/launcher): runs from the host venv while building, baked into the Docker image when triage joins a DAG. (Prod: for connected GitHub repos, the GitHub dependency-graph SBOM API replaces cloning — same `parse_spdx` downstream; see "Production target".)
- Version matching (Stage 4b, DECIDED): **`univers`** (from the packageurl authors) parses GHSA's `vulnerable_range` per ecosystem via `build_range_from_github_advisory_constraint(scheme, range)` and checks membership. PURL types already equal univers scheme names, so version math needs no mapping; `ECOSYSTEM_MAP` (pypi→pip, golang→go, cargo→rust, gem→rubygems) maps PURL→GHSA spelling only for the SQL join. Matching = one indexed join (`ix_affected_ecosystem_package`) + univers filter; measured ~40 ms for 822 deps.
- LLM triage (Stage 4c, DECIDED): candidate findings are **batched** into few LLM calls and **prioritized by severity** (critical/high first). Provider-agnostic `reason()` + BYO-key, default **Gemini 3 Flash** free tier, via the `google-genai` SDK. Findings + per-project memory persisted; idempotent (findings keyed by project×dependency×advisory).

**OPEN (not yet decided, ask the owners before acting):**
- Nothing outstanding right now. If a new fork appears, it lands here until the owners decide.

**DEFERRED (decide when we reach the stage, not before):**
- Which metrics and dashboards (Stage 5)
- (Embedding model + agent design moved to DECIDED / AGREED PLAN above.)

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
- Schema changes go through Alembic migrations. The pgvector embedding dimension is now fixed at **1024** (Qwen3-Embedding-0.6B) — see the Decision Log.
- Migrated in so far: the Stage 2 schema (`advisories` + `affected`) and the Stage 3 pgvector column (`advisories.embedding` 1024-dim + `embedded_at` + HNSW index). Stage 4 will add `projects`, `dependencies`, `findings`, `agent_memory` (owners' call). Future schema changes still go through Alembic and remain the owners' call; propose and advise, don't finalize tables on your own.

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

Grouped as three phases across six stages. **Currently: Phase 2, Stage 4 (the triage agent).** We're building toward production (see "Production target"), still in sequence.

**Phase 1, data spine (Stages 0-2). ✅ DONE.**
- Stage 0 — ✅ **done**: two-Postgres + Airflow LocalExecutor compose, `depwatch/config.py`, a hello-world DAG running green (`dags/hellow_world.py`), Alembic wired to `appdb`.
- Stage 1 — ✅ **done (core)**: **Stage 1a** — GHSA advisories → raw JSON in MinIO, run daily by `dags/ingest_ghsa.py` with a watermark. OSV bulk-zip dumps → raw JSON in MinIO too, run daily by `dags/ingest_osv.py` (`depwatch/sources/osv.py`: `fetch_dump` downloads+unzips one ecosystem, `fetch_dumps` loops several, `ingest_raw` lands one `osv/dt=<date>/<ecosystem>.json` object per ecosystem). No watermark for OSV — its zips are always a full daily snapshot, not incrementally queryable like GHSA's API. Ecosystem list is currently hardcoded to `["PyPI"]` in the DAG — placeholder pending which ecosystem(s) ImpactTrail/Rainfall actually need. **Stage 1b** — `record_to_rows` + `upsert_advisory` + `load_ghsa` load raw MinIO JSON → `advisories` + `affected` via upsert; **33,874 advisories / 62,857 affected** loaded, idempotent (GHSA only so far). *Parked:* `record_to_rows` pytest, an OSV equivalent of `load_ghsa` (loading OSV's raw MinIO JSON into Postgres), NVD enrichment.
- Stage 2 — ✅ **done**: Postgres schema designed and migrated — `advisories` + `affected` (see the Decision Log and README "Schema"). Models in `depwatch/storage/postgres.py`, `alembic/env.py` wired to `Base.metadata`, migration `6ec38f936a6a` applied.

**Phase 2, AI layer (Stages 3-4). CURRENT.**
- Stage 3 — ✅ **done**: Qwen3-Embedding-0.6B (local, 1024-dim) embeds advisory text into `advisories.embedding`; incremental via `embedded_at`; filter-then-rank retrieval (`depwatch/embedding/retrieve.py` `search()`); HNSW index. Runs on the Mac GPU via the Route B host launcher + launchd. Migrations `502c5084a4e0` + `43c9f0a95612`. Committed `c283d66`.
- Stage 4 — 🔨 **in progress**: the triage agent. **4a ✅** (clone+scalibr → parse PURLs → `projects`/`dependencies`, idempotent). **4b ✅** (indexed join + `univers` version-in-range → candidate findings; 155 real on HackBeanPot). **4c** (LLM judgment — batched + severity-prioritized, Gemini default, `findings`/`agent_memory` tables) and **4d** (CLI/DAG triggers + per-project memory) remaining.

**Phase 3, observability (Stage 5).**
- Prometheus instrumentation everywhere, Grafana dashboards. The owners pick the metrics. Done when one dashboard shows the whole system alive.

**Stage 6, validation.** Trivy diff harness + container scanning, once there are findings to compare.

Prepare for scale in our *choices*, but still build in *sequence*: don't build production infra (ECS, auth, multi-tenancy) before the core engine works. Flag later ideas and architect so they're not precluded — but finish the current stage first. Half-built infra with no working engine is the most likely way this project dies.

---

## Production target (future — prepare for, don't build yet)

Where this is headed once the core engine works. We build local-first, but nothing here should require a rewrite — just deployment. Local dev → production mapping:

- **Orchestration:** Docker Compose → **ECS Fargate** (serverless containers; chosen over EKS — Kubernetes ops is overkill at our scale). Images in ECR, infra in Terraform/CDK.
- **App DB:** `appdb` pgvector container → **RDS/Aurora Postgres** with the pgvector extension.
- **Raw storage:** MinIO → **S3** (drop-in; we already use the S3 API).
- **Batch pipeline:** Airflow LocalExecutor → **Amazon MWAA** (managed Airflow) or Airflow on ECS.
- **Embeddings:** Route B Mac-GPU launcher → a **GPU embedding microservice** (GPU ECS task / SageMaker / serverless GPU), called over HTTP like Route B — or a paid embedding API if cheaper at our volume.
- **Triage engine:** the `triage(repo_url)` function stays; interactive path becomes a **FastAPI service** behind an ALB; batch re-scans stay a scheduled task.
- **Repo ingestion (hosted flow):** "Sign in with GitHub" (OAuth) for identity + a **GitHub App** the user installs on their chosen repos (least-privilege: Contents/Metadata/Dependency-graph read). The App's installation token reads each repo's **dependency-graph SBOM via API → NO cloning**, no untrusted code on our servers. `clone + scalibr` stays the adapter for local dev and any non-connected/arbitrary repo. Both front-ends feed the **same** `parse_spdx → match → triage` engine (the swappable extraction seam). NOTE: fine-grained tokens can't reach repos the user doesn't own, so the SBOM API only serves *connected* repos — hence the App-install model rather than "paste any URL."
- **Untrusted repos (fallback clone path):** if we ever clone (dev, or non-GitHub), do it in a **sandboxed, ephemeral, egress-restricted task** — clone + `scalibr` only, **never execute repo code**, no secrets mounted.
- **Multi-tenancy:** **GitHub OAuth** for auth (identity + repo access in one), per-user data isolation, rate limits/quotas, **BYO-key** so users fund their own LLM calls.
- **Secrets:** `.env` → **Secrets Manager / SSM**.
- **Observability:** self-run Prometheus+Grafana → **managed Prometheus + managed Grafana** (or CloudWatch).

Aspirational and sequenced *after* the core stages — listed so today's choices stay production-compatible.

## Watched projects

`projects/` holds the dependency files of the repos DepWatch monitors. First targets: ImpactTrail and Rainfall. Get ImpactTrail working end to end first, then add Rainfall.

## Non-goals (for now) — future-prepared

We're building toward production, so some former "never"s are now "later, and we architect for them":

- **Multi-tenant, auth, user accounts** — a future stage (the hosted "paste your repo" service). Not built yet, but we make choices that don't preclude it (stateless engine, config via env, per-tenant-ready schema). See "Production target (future)".
- Not real time; daily batch is fine and matches the sources.
- Not big data by volume *yet*; we build the patterns (idempotency, raw vs. curated, partitioning) so they scale cleanly when volume grows.
- Not trying to beat Dependabot or Snyk on day one; prior art existing means the problem is real — we earn scale by shipping the core first.

## Definition of done for any task

1. It runs.
2. It's idempotent if it writes data.
3. It has a test if it contains logic.
4. It emits a metric if it's a pipeline step (from Stage 5 on).
5. Both of us could explain the design choice in an interview without hand-waving.