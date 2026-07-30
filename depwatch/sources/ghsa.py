"""GitHub Security Advisories (GHSA): fetch reviewed advisories from the REST API.

Docs: https://docs.github.com/en/rest/security-advisories/global-advisories
"""

from collections.abc import Iterator
from datetime import date

import requests

from depwatch import config
from depwatch.storage.minio import miniIO

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
    will call. Objects are keyed by ingest date: github/dt=<today>/advisories_p<n>.json.
    `updated_since` does incremental pulls; `max_pages` caps the crawl (for testing).

    Returns {"pages": <int>, "newest_updated": <str|None>}: the page count (for
    logging) and the newest advisory's updated_at — the next watermark, None when empty.
    """
    store = miniIO()
    store.ensure_bucket()

    today = date.today().isoformat()
    pages = 0
    newest_updated: str | None = None
    for pages, page in enumerate(fetch_advisories(updated_since), start=1):
        if pages == 1 and page:  # sorted updated desc -> first advisory is the newest
            newest_updated = page[0]["updated_at"]
        store.insertJSON(f"github/dt={today}/advisories_p{pages}.json", page)
        if max_pages and pages >= max_pages:
            break
    return {"pages": pages, "newest_updated": newest_updated}