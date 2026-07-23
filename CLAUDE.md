# CLAUDE.md

Project context for Claude Code. Read this before doing anything in this repo.

---

## What this project is

DepWatch is a small vulnerability intelligence platform. It ingests public security advisories every day, indexes them for semantic search, and uses an LLM agent to tell us which dependencies in our own projects are actually dangerous, whether we're realistically affected, and how long a finding has been open. Grafana monitors both the pipeline and the security posture over time.

Think "scoped-down Snyk, built to learn the architecture." It is not a product, it has no customers, and it does not need to scale.

---

## IMPORTANT: this is a learning project, work accordingly

Two rising sophomores are building this to learn data engineering and applied AI. If you write all the code, the project fails at its actual purpose even if the code works.

**Default working mode:**
- Explain the approach and the tradeoffs BEFORE writing code, and wait for a go-ahead on anything non-trivial.
- Prefer scaffolding over finished implementations: correct structure, clear function signatures, docstrings explaining what goes where, and `TODO` markers for the interesting logic. Let us fill in the core logic ourselves.
- When you do write a full implementation (fine for boilerplate, config, Dockerfiles, glue), explain the parts that are new to us, especially anything Airflow-specific, pgvector-specific, or Prometheus-specific.
- When there are several reasonable ways to do something, say so and give a recommendation with a reason. Do not silently pick one.
- If we ask for something that's a bad idea, say so directly. Do not just build it.

**Full autonomous implementation is fine for:** config files, Docker/compose setup, test fixtures, type hints, docstrings, refactors we explicitly ask for, and debugging errors we're stuck on.

**Stop and ask us first for:** database schema changes, adding a new dependency or service to the stack, changing the agent's prompt strategy, and anything that touches more than about three files.

---

## Architecture

```
  sources                 ingest              store                index            reason              observe
┌──────────────┐      ┌───────────┐      ┌────────────┐      ┌───────────┐    ┌────────────┐    ┌────────────┐
│ GHSA API     │─────▶│           │─────▶│ MinIO      │      │           │    │            │    │            │
│ OSV.dev dump │─────▶│  Airflow  │      │ (raw JSON) │      │ pgvector  │───▶│ LLM agent  │───▶│  Grafana   │
│ NVD API      │─────▶│   DAGs    │─────▶│ Postgres   │─────▶│  index    │    │  + memory  │    │ Prometheus │
└──────────────┘      └───────────┘      │ (clean)    │      └───────────┘    └────────────┘    └────────────┘
                                          └────────────┘                             │                  ▲
                                                                                      └──── findings ────┘
```

Flow in words: Airflow DAGs pull advisories daily, land raw JSON in MinIO and normalized rows in Postgres, embed advisory text into pgvector, then the agent takes a project's dependency file, retrieves relevant advisories, reasons about real impact, and writes findings plus per-project memory back to Postgres. Everything emits Prometheus metrics that Grafana renders.

---

## Stack (decided, do not change without asking)

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.13 | Airflow's native language |
| Orchestration | Apache Airflow 2.x (official Docker image) | Real scheduled multi-step workflows with retries and backfills |
| Relational store | Postgres 16 | Normalized advisories, projects, findings, memory |
| Vector store | pgvector extension on the same Postgres | Keeps the stack to one database, one less service to run |
| Object storage | MinIO (S3-compatible, local) | Raw JSON landing zone, teaches the lake pattern without AWS billing |
| Embeddings | `sentence-transformers`, `all-MiniLM-L6-v2` (384 dims, CPU, free) | No API key, no cost, good enough for advisory text |
| LLM | Anthropic API via the `anthropic` SDK | Model configurable via env var, cheaper/faster model for bulk triage |
| Metrics | Prometheus | Scrapes every component |
| Dashboards | Grafana | Two dashboards: system health, security posture |
| Packaging | Docker Compose | `docker compose up` brings up the whole platform |
| Deps | `requirements.txt`, pinned versions | Matches Airflow's Docker image conventions |

---

## Repo structure

```
depwatch/
├── docker-compose.yml
├── .env.example              # every env var, with fake values. NEVER commit .env
├── dags/                     # Airflow DAGs, thin orchestration only
│   ├── ingest_ghsa.py
│   ├── ingest_osv.py
│   ├── enrich_nvd.py
│   └── embed_advisories.py
├── depwatch/                 # the actual library, importable and testable
│   ├── sources/              # one client per data source
│   ├── transform/            # normalization into our schema
│   ├── storage/              # Postgres + MinIO access
│   ├── embedding/            # embedding + vector search
│   ├── agent/                # retrieval, prompts, triage loop, memory
│   └── metrics/              # Prometheus instrumentation
├── sql/                      # schema migrations, numbered, forward-only
├── monitoring/               # prometheus.yml, grafana dashboards as JSON
├── tests/
└── projects/                 # dependency files of the repos we watch
```

**Rule: DAGs stay thin.** A DAG file wires tasks together and handles scheduling. All real logic lives in `depwatch/` so it can be unit tested without spinning up Airflow. If a DAG file is over about 60 lines of logic, it's in the wrong place.

---

## Data sources (verified, use these exact facts)

**GitHub Security Advisories, primary.**
`GET https://api.github.com/advisories` with `Accept: application/vnd.github+json`. Works unauthenticated at 60 req/hour, 5000 req/hour with a free personal access token. Paginate via the `Link` header. Gives us `ghsa_id`, `cve_id`, `severity`, `summary`, `description`, `vulnerabilities[]` with package ecosystem, name, vulnerable version range, and first patched version. This is the richest source for our use case because it's keyed by package, which is exactly how we look things up.

**OSV.dev, primary.**
Bulk zip dumps at `https://storage.googleapis.com/osv-vulnerabilities/{ECOSYSTEM}/all.zip` (for example `PyPI`, `npm`, `Go`, `Maven`), refreshed daily. There's also a query API at `https://api.osv.dev/v1/query` and a batch endpoint. Prefer the bulk zips for ingestion since a file can't rate-limit you. Records follow the OSV schema, which is well documented and stable.

**NVD, enrichment only.**
`https://services.nvd.nist.gov/rest/json/cves/2.0`. Free API key from `https://nvd.nist.gov/developers/request-an-api-key`. Rate limits are 5 requests per rolling 30 seconds without a key, 50 with one, so sleep between requests. Use the `lastModStartDate` / `lastModEndDate` params for incremental syncs, which is NIST's own recommended pattern. We use NVD for CVSS scores and extra references, keyed by CVE ID.

**Why NVD is not primary:** it identifies software with CPE strings, which are painful to match against a `package.json`. GHSA and OSV are keyed by package name and version range directly. Merging all three also gives us a genuine multi-source reconciliation problem to solve, which is the point.

**Never fabricate advisory data.** If you need example data for a test, either use a real record pulled from the API or clearly name the fixture something like `FAKE_ADVISORY_FOR_TESTS`. Made-up CVE IDs that look real are a trap for us later.

---

## Trivy: benchmark, not engine

Trivy is in this project as a **validation baseline and container scanner**, never as the core matching engine. Building our own ingestion and matching is the entire point of phases 1 and 2.

Approved uses:
- Run `trivy fs` against a watched repo, diff its findings against ours, and report agreement/disagreement. This is our eval harness.
- Run `trivy image` against our own service images for container-layer coverage our dependency-file pipeline doesn't have.
- Later (phase 3+ only), feed Trivy output into the agent as a second signal source alongside our own matcher.

If you ever find yourself suggesting "just call Trivy here" in place of our own retrieval or matching logic, stop and flag it instead.

---

## Database conventions

- Table names plural and snake_case: `advisories`, `projects`, `dependencies`, `findings`, `agent_memory`, `raw_ingest_log`.
- Every table gets `created_at timestamptz default now()` and, where mutable, `updated_at`.
- Advisories carry `source` and `source_id` with a unique constraint on the pair, so re-ingesting is safe.
- Embedding column is `vector(384)` to match `all-MiniLM-L6-v2`. If we swap models, the dimension changes and needs a migration.
- Migrations live in `sql/` as numbered forward-only files (`001_init.sql`, `002_add_findings.sql`). No ORM, plain SQL, so we actually learn it.

## Airflow conventions

- **Every DAG must be idempotent.** Re-running any task for any date must not duplicate rows. Use upserts keyed on `(source, source_id)`.
- Incremental by default, using a watermark of the last successful run. Full refresh only as an explicitly triggered separate DAG.
- Set `retries` and `retry_delay` on every task that touches a network. These APIs are occasionally flaky and handling that is a feature of the project, not a bug.
- Tasks log counts (fetched, inserted, updated, skipped) and export them as Prometheus metrics.
- No secrets in DAG code. Everything through env vars or Airflow connections.

## Agent conventions

- Agent output must be **structured**, a typed finding object, not a wall of prose. Fields at minimum: package, installed version, advisory ID, severity, our assessed urgency, affected (yes/no/unsure), reasoning, recommended action.
- Memory is per project and per advisory. On each run, look up prior findings first, so the agent can say "still unpatched, day 12" and remember prior calls like "assessed not reachable, because we never call the affected function."
- Prompts live in versioned files under `depwatch/agent/prompts/`, not inline in code, so we can diff them when quality changes.
- Log every LLM call's token usage and cost to Postgres. It feeds a Grafana panel and keeps us honest about spend.
- The agent must be allowed to say "I'm not sure." A confident wrong triage is worse than an unsure one.

## Code conventions

- Type hints on all function signatures. `ruff` for linting and formatting.
- Small pure functions in `transform/`, tested with plain pytest. No test needs Docker running.
- Config via env vars, read once in one place (`depwatch/config.py`), never scattered `os.getenv` calls.
- Comments explain *why*, not *what*.

---

## Commands

```bash
docker compose up -d              # bring up the whole platform
docker compose logs -f airflow-scheduler
make migrate                      # apply sql/ migrations in order
make test                         # pytest
make lint                         # ruff check + format
make dag-test DAG=ingest_ghsa     # run one DAG locally without the scheduler
trivy fs projects/impacttrail     # baseline scan for comparison
```

Airflow UI at `localhost:8080`, Grafana at `localhost:3000`, MinIO console at `localhost:9001`.

---

## Roadmap and current phase

**Phase 1, data spine (weeks 1-3). CURRENT PHASE.**
Airflow DAGs for GHSA and OSV, raw landing in MinIO, normalized rows in Postgres, NVD enrichment. Done when fresh advisories land daily with no human involvement and re-runs don't duplicate anything.

**Phase 2, AI layer (weeks 3-6).**
Embeddings into pgvector, retrieval, the agent triage loop, structured findings, per-project memory. Done when pointing it at one of our repos produces a report that makes sense to a human.

**Phase 3, observability (weeks 6-8).**
Prometheus instrumentation everywhere, two Grafana dashboards (system health, security posture). Done when one dashboard shows the whole system alive.

**Stretch, only after phase 3.** Web UI, Discord notifications, reachability analysis against actual source code, CI integration, Trivy as a second signal.

**Do not build ahead.** If we're in phase 1 and you're tempted to add an agent call or a Grafana panel, don't. Flag it as a phase 2/3 item instead. Scope creep is the single most likely way this project dies.

---

## Watched projects

`projects/` holds the dependency files of the repos DepWatch monitors. First targets are our own: ImpactTrail and Rainfall. Start with one, get it fully working end to end, then add the second.

---

## Non-goals

- Not multi-tenant, no auth, no user accounts.
- Not real time. Daily is fine, and daily is what the sources publish anyway.
- Not big data by volume. We design with the patterns (partitioning, idempotency, raw vs. curated) at small scale, deliberately.
- Not trying to beat Dependabot or Snyk. Prior art exists and that's fine, it means the problem is real.

## Definition of done for any task

1. It runs.
2. It's idempotent if it writes data.
3. It has a test if it contains logic.
4. It emits a metric if it's a pipeline step.
5. Both of us could explain the design choice in an interview without hand-waving.

If a change can't clear all five, say so before we merge it.
