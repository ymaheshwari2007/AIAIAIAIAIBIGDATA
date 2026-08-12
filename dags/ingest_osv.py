from datetime import datetime, timedelta

from airflow.sdk import dag, task

from depwatch.sources.osv import ingest_raw

ECOSYSTEMS = ["PyPI"]  # TODO: match whatever ImpactTrail/Rainfall actually use

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
    print(f"landed {count} ecosystem(s)")
  ingest()
OSV()
