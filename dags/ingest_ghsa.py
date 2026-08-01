from datetime import datetime, timedelta, date
from airflow.sdk import dag, task, Variable  

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
    watermark = new['newest_updated']
    if watermark:
      Variable.set(watermark_key, watermark)
    
    return date.today().isoformat()
  @task
  def load(dt: str):
    load_ghsa(dt)
  load(ingest())
GHSA()