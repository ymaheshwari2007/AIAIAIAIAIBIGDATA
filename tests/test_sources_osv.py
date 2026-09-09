"""Unit tests for OSV ingestion (depwatch/sources/osv.py).

Pure unit tests: no network, no MinIO, no Docker, no Postgres. requests.get is
monkeypatched to return a fake response wrapping a real in-memory zip (so
fetch_dump's own unzip/JSON-parse logic still runs), and miniIO/session_scope/
upsert_advisory are monkeypatched to small fakes that record what would have
happened, so ingest_raw's and load_osv's own looping/aggregation logic runs
without touching a real bucket or database. load_osv's tests still run the real
record_to_rows against the fake records, to confirm the two are wired together
correctly end to end (minus the actual I/O).
"""

import io
import json
import zipfile
from contextlib import contextmanager
from datetime import date

import pytest
import requests

from depwatch.sources import osv

FAKE_ADVISORY_FOR_TESTS = {
    "id": "OSV-2026-0001",
    "summary": "Fake advisory used only in tests",
}


def _make_zip(records: dict[str, dict]) -> bytes:
    """Build an in-memory zip: one JSON file per (filename, record) pair."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, record in records.items():
            archive.writestr(name, json.dumps(record))
    return buf.getvalue()


class _FakeResponse:
    def __init__(self, content: bytes, error: Exception | None = None):
        self.content = content
        self._error = error

    def raise_for_status(self):
        if self._error is not None:
            raise self._error


class _FakeMiniIO:
    """Stands in for depwatch.storage.minio.miniIO — no real bucket touched."""

    def __init__(self):
        self.ensure_bucket_calls = 0
        self.inserted: dict[str, object] = {}

    def ensure_bucket(self):
        self.ensure_bucket_calls += 1

    def insertJSON(self, key, obj):
        self.inserted[key] = obj


def test_fetch_dump_parses_zip_contents(monkeypatch):
    zip_bytes = _make_zip({"OSV-2026-0001.json": FAKE_ADVISORY_FOR_TESTS})
    monkeypatch.setattr(osv.requests, "get", lambda url: _FakeResponse(zip_bytes))

    records = osv.fetch_dump("PyPI")

    assert records == [FAKE_ADVISORY_FOR_TESTS]


def test_fetch_dump_raises_on_http_error(monkeypatch):
    error = requests.HTTPError("404 Not Found")
    monkeypatch.setattr(
        osv.requests, "get", lambda url: _FakeResponse(b"", error=error)
    )

    with pytest.raises(requests.HTTPError):
        osv.fetch_dump("PyPI")


def test_fetch_dumps_yields_ecosystem_pairs(monkeypatch):
    data_by_ecosystem = {
        "PyPI": [FAKE_ADVISORY_FOR_TESTS],
        "npm": [{"id": "OSV-2026-0002", "summary": "Another fake advisory"}],
    }
    monkeypatch.setattr(
        osv, "fetch_dump", lambda ecosystem: data_by_ecosystem[ecosystem]
    )

    result = list(osv.fetch_dumps(["PyPI", "npm"]))

    assert result == [
        ("PyPI", data_by_ecosystem["PyPI"]),
        ("npm", data_by_ecosystem["npm"]),
    ]


def test_ingest_raw_writes_one_object_per_ecosystem(monkeypatch):
    data_by_ecosystem = {
        "PyPI": [FAKE_ADVISORY_FOR_TESTS],
        "npm": [{"id": "OSV-2026-0002", "summary": "Another fake advisory"}],
    }
    fake_store = _FakeMiniIO()
    monkeypatch.setattr(osv, "miniIO", lambda: fake_store)
    monkeypatch.setattr(
        osv, "fetch_dump", lambda ecosystem: data_by_ecosystem[ecosystem]
    )

    count = osv.ingest_raw(["PyPI", "npm"])

    today = date.today().isoformat()
    assert fake_store.ensure_bucket_calls == 1
    assert fake_store.inserted == {
        f"osv/dt={today}/PyPI.json": data_by_ecosystem["PyPI"],
        f"osv/dt={today}/npm.json": data_by_ecosystem["npm"],
    }
    # ingest_raw returns a plain count of ecosystems processed, not a dict
    # (the docstring is stale/copy-pasted from GHSA's ingest_raw and describes
    # a {"pages": .., "newest_updated": ..} shape that doesn't match reality).
    assert count == 2


def test_ingest_raw_empty_ecosystems_returns_zero(monkeypatch):
    fake_store = _FakeMiniIO()
    monkeypatch.setattr(osv, "miniIO", lambda: fake_store)

    count = osv.ingest_raw([])

    assert fake_store.ensure_bucket_calls == 1
    assert fake_store.inserted == {}
    assert count == 0


class _FakeMiniIOForLoad:
    """Stands in for miniIO on the read side: pre-loaded key -> record-list pages."""

    def __init__(self, keys_to_pages: dict[str, list[dict]]):
        self._keys_to_pages = keys_to_pages
        self.listKeys_calls: list[str] = []

    def listKeys(self, prefix):
        self.listKeys_calls.append(prefix)
        return list(self._keys_to_pages.keys())

    def readJSON(self, key):
        return self._keys_to_pages[key]


@contextmanager
def _fake_session_scope():
    yield "fake-session"  # load_osv only ever passes this through to upsert_advisory


FAKE_ADVISORY_FOR_TESTS_1 = {"id": "OSV-TEST-1001", "summary": "fake for load_osv test"}
FAKE_ADVISORY_FOR_TESTS_2 = {"id": "OSV-TEST-1002", "summary": "fake for load_osv test"}
FAKE_ADVISORY_FOR_TESTS_3 = {"id": "OSV-TEST-1003", "summary": "fake for load_osv test"}


def test_load_osv_reads_and_upserts_every_record(monkeypatch):
    fake_store = _FakeMiniIOForLoad(
        {
            "osv/dt=2026-09-09/PyPI.json": [
                FAKE_ADVISORY_FOR_TESTS_1,
                FAKE_ADVISORY_FOR_TESTS_2,
            ],
            "osv/dt=2026-09-09/npm.json": [FAKE_ADVISORY_FOR_TESTS_3],
        }
    )
    monkeypatch.setattr(osv, "miniIO", lambda: fake_store)
    monkeypatch.setattr(osv, "session_scope", _fake_session_scope)

    upsert_calls = []
    monkeypatch.setattr(
        osv,
        "upsert_advisory",
        lambda session, advisory, affected: upsert_calls.append(
            (session, advisory, affected)
        ),
    )

    result = osv.load_osv(dt="2026-09-09")

    assert fake_store.listKeys_calls == ["osv/dt=2026-09-09/"]
    assert result == {"pages": 2, "advisories": 3}
    # record_to_rows ran for real on each fake record -- confirms the two are wired
    # together correctly, not just that load_osv "called something 3 times"
    assert {advisory["source_id"] for _, advisory, _ in upsert_calls} == {
        "OSV-TEST-1001",
        "OSV-TEST-1002",
        "OSV-TEST-1003",
    }
    assert all(advisory["source"] == "osv" for _, advisory, _ in upsert_calls)
    assert all(session == "fake-session" for session, _, _ in upsert_calls)


def test_load_osv_no_dt_lists_whole_prefix_and_handles_no_data(monkeypatch):
    fake_store = _FakeMiniIOForLoad({})
    monkeypatch.setattr(osv, "miniIO", lambda: fake_store)
    monkeypatch.setattr(osv, "session_scope", _fake_session_scope)
    monkeypatch.setattr(osv, "upsert_advisory", lambda *args: None)

    result = osv.load_osv()

    assert fake_store.listKeys_calls == ["osv/"]  # not "osv/dt=None/"
    assert result == {"pages": 0, "advisories": 0}
