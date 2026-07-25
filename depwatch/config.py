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
