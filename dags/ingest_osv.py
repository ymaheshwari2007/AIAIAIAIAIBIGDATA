from datetime import date, datetime, timedelta

from airflow.sdk import dag, task

from depwatch.sources.osv import ingest_raw, load_osv

ECOSYSTEMS = ["PyPI"]  # TODO: find a way to change ecosystem based on repo


@dag(
    schedule="@daily",
    start_date=datetime(2025, 1, 1),
    catchup=False,
    max_active_runs=1,
    default_args={"retries": 3, "retry_delay": timedelta(minutes=5)},
    tags=["stage1", "ingest", "osv"],
)
def OSV():
    @task
    def ingest():
        count = ingest_raw(ECOSYSTEMS)
        # print(f"landed {count} ecosystem(s)")
        return date.today().isoformat()

    @task
    def load(dt: str):
        result = load_osv(dt)
        print(f"loaded {result['advisories']} advisories from {result['pages']} object(s)")

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


OSV()
