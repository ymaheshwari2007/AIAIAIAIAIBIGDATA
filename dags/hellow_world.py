from datetime import datetime
from airflow.sdk import dag, task

@dag(
    schedule=None,
    start_date=datetime(2025, 1, 1),
    catchup=False,
    tags=["stage0", "hello"],
)

def helloword():
  @task
  def sayhello():
    print("hellow from this device just tryying shiiiiiiits")
  
  sayhello()

helloword()
