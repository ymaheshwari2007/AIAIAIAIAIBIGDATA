FROM apache/airflow:3.3.0-python3.13

# The deps our DAGs import at runtime that aren't already in the Airflow image.
# (requests is already there.) NOT installing sqlalchemy/psycopg2/alembic — those
# are host-only (Alembic, pytest) and would risk clashing with Airflow's own pins.
# depwatch itself isn't baked in; it's bind-mounted via docker-compose.
RUN pip install --no-cache-dir minio==7.2.20 python-dotenv==1.2.2