"""GitHub Security Advisories (GHSA): fetch reviewed advisories from the REST API.

Docs: https://docs.github.com/en/rest/security-advisories/global-advisories
"""

from collections.abc import Iterator
from datetime import date, datetime

import requests

from depwatch import config
from depwatch.storage.minio import miniIO
from depwatch.storage.postgres import session_scope, upsert_advisory
from depwatch.transform.ghsa import record_to_rows

API_URL = "https://api.github.com/advisories"


def _headers() -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {config.github_token()}",
    }


def fetch_advisories(updated_since: str | None = None) -> Iterator[list[dict]]:
    """Yield each page of reviewed advisories until GitHub has no more.

    Pages are cursor-paginated via the Link header. `updated_since` is a bare
    timestamp (e.g. "2026-07-01"); we prepend GitHub's ">=" so it means "changed
    since then" — how the daily DAG does incremental pulls. None = full backfill.
    """
    params = {
        "per_page": 100,
        "sort": "updated",
        "direction": "desc",
        "type": "reviewed",
    }
    if updated_since:
        params["updated"] = f">={updated_since}"

    # first page: send our params
    resp = requests.get(API_URL, headers=_headers(), params=params)
    resp.raise_for_status()
    yield resp.json()

    # follow GitHub's "next" cursor until it stops handing us one
    while "next" in resp.links:
        next_url = resp.links["next"]["url"]  # already carries per_page + cursor
        resp = requests.get(next_url, headers=_headers())  # no params: they're in the url
        resp.raise_for_status()
        yield resp.json()


def ingest_raw(updated_since: str | None = None, max_pages: int | None = None) -> dict:
    """Fetch advisories and land each raw page as a JSON object in MinIO.

    Ties fetch_advisories() to the MinIO wrapper — the GHSA ingest the thin DAG
    will call. Objects are keyed by ingest date + a per-run token:
    github/dt=<today>/run=<HHMMSS>/advisories_p<n>.json, so a later run never
    overwrites an earlier run's pages (raw stays append-only).
    `updated_since` does incremental pulls; `max_pages` caps the crawl (for testing).

    Returns {"pages": <int>, "newest_updated": <str|None>}: the page count (for
    logging) and the newest advisory's updated_at — the next watermark, None when empty.
    """
    store = miniIO()
    store.ensure_bucket()

    today = date.today().isoformat()
    run = datetime.now().strftime("%H%M%S")  # per-run token: keeps runs from overwriting each other's pages
    pages = 0
    newest_updated: str | None = None
    for pages, page in enumerate(fetch_advisories(updated_since), start=1):
        if pages == 1 and page:  # sorted updated desc -> first advisory is the newest
            newest_updated = page[0]["updated_at"]
        store.insertJSON(f"github/dt={today}/run={run}/advisories_p{pages}.json", page)
        if max_pages and pages >= max_pages:
            break
    return {"pages": pages, "newest_updated": newest_updated}


def load_ghsa(dt: str | None = None) -> dict:
    """Load landed raw GHSA JSON from MinIO into Postgres (advisories + affected).

    Lists every page object under an ingest-date partition (all GHSA partitions when
    dt is None), transforms each advisory, and upserts it. Idempotent via the
    (source, source_id) upsert. Commits per page, so a failure mid-load keeps the
    pages already done. Returns {"pages": n, "advisories": n}.
    """
    store = miniIO()
    prefix = f"github/dt={dt}/" if dt else "github/"
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