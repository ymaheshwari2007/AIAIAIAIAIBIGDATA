FROM apache/airflow:3.3.0-python3.13

# Runtime deps our DAGs import that aren't already in the Airflow image.
# (requests is already there; sqlalchemy + psycopg2 come with Airflow.) pgvector is
# needed to import our models (postgres.py). Embedding runs on the HOST via the embed
# launcher service, so torch/sentence-transformers are deliberately NOT here.
RUN pip install --no-cache-dir minio==7.2.20 python-dotenv==1.2.2 pgvector==0.5.0