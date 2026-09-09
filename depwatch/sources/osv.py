"""OSV.dev: fetch vulnerability dumps from the public bulk-export bucket.

Docs: https://google.github.io/osv.dev/data/#zip-files
"""

import io
import json
import zipfile
from collections.abc import Iterator
from datetime import date

import requests

from depwatch.storage.minio import miniIO
from depwatch.storage.postgres import session_scope, upsert_advisory
from depwatch.transform.osv import record_to_rows

DUMP_URL = "https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip"


def fetch_dump(ecosystem: str) -> list[dict]:
    """Download one ecosystem's bulk zip and return every vulnerability record inside it.

    OSV ships one JSON file per vulnerability, bundled into a single zip per
    ecosystem (e.g. "PyPI", "npm"), refreshed daily. No pagination and no auth
    needed here — it's a plain public file, unlike GHSA's rate-limited API.
    """
    response = requests.get(DUMP_URL.format(ecosystem=ecosystem))
    response.raise_for_status()

    records = []
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        for name in archive.namelist():
            with archive.open(name) as f:
                records.append(json.load(f))
    return records


def fetch_dumps(ecosystems: list[str]) -> Iterator[tuple[str, list[dict]]]:
    """Yield (ecosystem, records) for each ecosystem in turn."""
    for ecosystem in ecosystems:
        yield ecosystem, fetch_dump(ecosystem)


def ingest_raw(ecosystems: list[str]) -> int:
    """Fetch each ecosystem's bulk dump and land it as one JSON object in MinIO.

    Ties fetch_dumps() to the MinIO wrapper — the OSV ingest the thin DAG will call.
    Objects are keyed by ingest date: osv/dt=<today>/<ecosystem>.json, one object per
    ecosystem (unlike GHSA's per-page objects — OSV's dumps aren't paginated).

    Returns the number of ecosystems processed.
    """
    store = miniIO()
    store.ensure_bucket()

    today = date.today().isoformat()
    count = 0
    for count, (ecosystem, records) in enumerate(fetch_dumps(ecosystems), start=1):
        store.insertJSON(f"osv/dt={today}/{ecosystem}.json", records)
    return count


def load_osv(dt: str | None = None) -> dict:
    store = miniIO()
    prefix = f"osv/dt={dt}/" if dt else "osv/"
    pages = 0
    loaded = 0
    for key in store.listKeys(prefix):
        page = store.readJSON(key)
        with session_scope() as session:
            for record in page:
                advisory, affected = record_to_rows(record)
                upsert_advisory(session, advisory, affected)
                loaded += 1
        pages += 1
    return {"pages": pages, "advisories": loaded}