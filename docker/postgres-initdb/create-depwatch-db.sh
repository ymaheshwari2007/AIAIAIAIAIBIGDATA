#!/bin/bash
# Postgres runs everything in this dir once, on the first boot of an empty
# data dir. The image already made the `airflow` db; here we add ours.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
	CREATE USER ${DEPWATCH_DB_USER} WITH PASSWORD '${DEPWATCH_DB_PASSWORD}';
	CREATE DATABASE ${DEPWATCH_DB_NAME} OWNER ${DEPWATCH_DB_USER};
SQL