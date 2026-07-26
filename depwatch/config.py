"""Single place we read configuration from the environment."""

import os

from dotenv import load_dotenv

load_dotenv()  # pull .env into the environment for host-side tools


def database_url() -> str:
    """Connection URL for the depwatch app database.

    Inside the Airflow containers compose sets DEPWATCH_DATABASE_URL (points at
    the `appdb` host). On your laptop it's unset, so we build a localhost URL
    from the parts in .env — that's how Alembic and pytest reach it.
    """
    url = os.environ.get("DEPWATCH_DATABASE_URL")
    if url:
        return url
    user = os.environ["DEPWATCH_DB_USER"]
    password = os.environ["DEPWATCH_DB_PASSWORD"]
    name = os.environ["DEPWATCH_DB_NAME"]
    # port 5433 matches the appdb host mapping in docker-compose.yaml (5432 is
    # commonly taken by a local Postgres).
    return f"postgresql+psycopg2://{user}:{password}@localhost:5433/{name}"


def github_token() -> str | None:
    """GitHub PAT for the advisories API (raises the rate limit to 5000/hr).

    Optional — unset means unauthenticated (60/hr). Set it in .env, never in code.
    """
    return os.environ.get("GITHUB_TOKEN") or None


def minio_settings() -> dict[str, str]:
    """Connection settings for MinIO, the raw landing zone.

    Endpoint is localhost:9000 from the host (venv); compose overrides it to
    minio:9000 inside the Airflow containers. Plain HTTP locally (secure=False).
    """
    return {
        "endpoint": os.environ.get("DEPWATCH_MINIO_ENDPOINT", "localhost:9000"),
        "access_key": os.environ.get("DEPWATCH_MINIO_ACCESS_KEY", "minioadmin"),
        "secret_key": os.environ.get("DEPWATCH_MINIO_SECRET_KEY", "minioadmin"),
        "bucket": os.environ.get("DEPWATCH_MINIO_BUCKET", "raw-advisories"),
    }
