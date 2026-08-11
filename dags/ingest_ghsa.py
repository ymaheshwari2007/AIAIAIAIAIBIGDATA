from datetime import date, datetime, timedelta

from airflow.sdk import Variable, dag, task

from depwatch.sources.ghsa import ingest_raw, load_ghsa

watermark_key = "GHSA_Updated"


@dag(
    schedule="@daily",
    start_date=datetime(2025, 1, 1),
    catchup=False,
    max_active_runs=1,
    default_args={"retries": 3, "retry_delay": timedelta(minutes=5)},
    tags=["stage1", "ingest", "ghsa"],
)
def GHSA():
    @task
    def ingest():
        watermark = Variable.get(watermark_key, default=None)
        new = ingest_raw(watermark)
        watermark = new["newest_updated"]
        if watermark:
            Variable.set(watermark_key, watermark)

        return date.today().isoformat()

    @task
    def load(dt: str):
        load_ghsa(dt)

    @task
    def embed():
        # embedding runs on the host GPU launcher (torch isn't in this image); we just POST.
        import os

        import requests

        url = os.environ.get(
            "DEPWATCH_EMBED_URL", "http://host.docker.internal:8000/embed"
        )
        resp = requests.post(url, timeout=600)
        resp.raise_for_status()
        return resp.json()

    loaded = load(ingest())
    loaded >> embed()


GHSA()
