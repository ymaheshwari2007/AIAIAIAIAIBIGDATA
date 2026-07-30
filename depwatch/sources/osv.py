"""OSV.dev: fetch vulnerability dumps from the public bulk-export bucket.

Docs: https://google.github.io/osv.dev/data/#zip-files
"""

from collections.abc import Iterator
from datetime import date

import io
import json
import zipfile

import requests

from depwatch.storage.minio import miniIO

DUMP_URL = "https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip"


def fetch_dump(ecosystem: str) -> list[dict]:
    """Download one ecosystem's bulk zip and return every vulnerability record inside it.

    OSV ships one JSON file per vulnerability, bundled into a single zip per
    ecosystem (e.g. "PyPI", "npm"), refreshed daily. No pagination and no auth
    needed here — it's a plain public file, unlike GHSA's rate-limited API.
    """
    respose = requests.get(DUMP_URL.format(ecosystem=ecosystem))
    respose.raise_for_status()

    records = []
    with zipfile.ZipFile(io.BytesIO(respose.content)) as archive:
        for name in archive.namelist():
            with archive.open(name) as f:
                records.append(json.load(f))
    return records


def fetch_dumps(ecosystems: list[str]) -> Iterator[tuple[str, list[dict]]]:
    """Yield (ecosystem, records) for each ecosystem in turn."""
    for ecosystem in ecosystems:
        yield ecosystem, fetch_dump(ecosystem)


def ingest_raw(ecosystems: list[str]) -> int:
    """Fetch advisories and land each raw page as a JSON object in MinIO.

    Ties fetch_advisories() to the MinIO wrapper — the GHSA ingest the thin DAG
    will call. Objects are keyed by ingest date: github/dt=<today>/advisories_p<n>.json.
    `updated_since` does incremental pulls; `max_pages` caps the crawl (for testing).

    Returns {"pages": <int>, "newest_updated": <str|None>}: the page count (for
    logging) and the newest advisory's updated_at — the next watermark, None when empty.
    """
    store = miniIO()
    store.ensure_bucket()

    today = date.today().isoformat()
    count = 0
    for count, (ecosystem, records) in enumerate(fetch_dumps(ecosystems), start=1):
        store.insertJSON(f"osv/dt={today}/{ecosystem}.json", records)
    return count
