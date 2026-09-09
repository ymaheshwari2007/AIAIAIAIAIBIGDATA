"""Normalize a raw OSV advisory record into rows for the `advisories` + `affected` tables.

Pure functions only — no DB, no MinIO, no network — so they unit-test with plain pytest.
Target columns live in depwatch/storage/postgres.py. Timestamps pass through as ISO
strings; Postgres casts them to timestamptz on insert.

OSV record shape (see https://ossf.github.io/osv-schema/) differs from GHSA's in a few
places that don't map 1:1. Records vary: GHSA-mirrored OSV records carry `severity` +
`database_specific`; native records (e.g. PYSEC-sourced) often have neither key at all,
so everything here defaults to {} / [] / None rather than assuming a field exists.
"""

SOURCE = "osv"


def _find_cve(aliases: list[str]) -> str | None:
    """OSV has no dedicated cve_id field — aliases mixes CVE/GHSA/PYSEC ids together."""
    return next((alias for alias in aliases if alias.startswith("CVE-")), None)


def _cvss_vector(severities: list[dict]) -> str | None:
    """Pick a CVSS vector string out of record["severity"], preferring CVSS_V3."""
    for entry in severities:
        if entry.get("type") == "CVSS_V3":
            return entry.get("score")
    return severities[0].get("score") if severities else None


def _primary_url(record: dict) -> str | None:
    """First WEB reference if there is one, else a constructed osv.dev link."""
    for ref in record.get("references") or []:
        if ref.get("type") == "WEB":
            return ref.get("url")
    return f"https://osv.dev/vulnerability/{record['id']}"


def _events_to_intervals(events: list[dict]) -> list[tuple[str | None, str | None]]:
    """Pair one range's chronological events into (introduced, fixed) intervals.

    OSV events are a flat, ordered list, e.g. [{"introduced": "0"}, {"fixed": "1.0"},
    {"introduced": "2.0"}, {"fixed": "3.0"}] — each "introduced" opens a vulnerable
    interval, closed by the next "fixed" or "last_affected". An interval still open at
    the end of the list (no closing event yet — unpatched) comes back with fixed=None.
    """
    intervals = []
    introduced = None
    for event in events:
        if "introduced" in event:
            introduced = event["introduced"]
        elif "fixed" in event or "last_affected" in event:
            intervals.append((introduced, event.get("fixed") or event.get("last_affected")))
            introduced = None
    if introduced is not None:
        intervals.append((introduced, None))
    return intervals


def _interval_to_range(introduced: str | None, fixed: str | None) -> str | None:
    """(introduced, fixed) -> a GHSA-style constraint string, e.g. ">= 1.2.0, < 2.0.0".

    Matches what univers.build_range_from_github_advisory_constraint() expects (see
    depwatch/agent/match.py). "0" as introduced means "from the start", not a real
    version, so it's dropped rather than emitted as ">= 0". An interval with neither
    bound (introduced "0"/None and no fixed — vulnerable everywhere, forever) comes
    back None; match.py already skips rows with no vulnerable_range.
    """
    parts = []
    if introduced and introduced != "0":
        parts.append(f">= {introduced}")
    if fixed:
        parts.append(f"< {fixed}")
    return ", ".join(parts) or None


def record_to_rows(record: dict) -> tuple[dict, list[dict]]:
    """Map one OSV advisory record to (advisory, affected).

    advisory: dict keyed by `advisories` columns. Omits id/created_at/updated_at —
      the DB default and the upsert own those.
    affected: one dict per affected package x version interval, keyed by `affected`
      columns, WITHOUT advisory_id — the loader fills that in after the advisory is
      upserted and we know its id.
    """
    severities = record.get("severity") or []
    db_specific = record.get("database_specific") or {}
    severity = db_specific.get("severity")

    advisory = {
        "source": SOURCE,
        "source_id": record["id"],  # required; a missing id means a broken record
        "cve_id": _find_cve(record.get("aliases") or []),
        "summary": record.get("summary"),
        "description": record.get("details"),
        "severity": severity.lower() if severity else None,
        "cvss_score": None,  # OSV gives a CVSS vector string only, never a plain score
        "cvss_vector": _cvss_vector(severities),
        "epss_score": None,  # OSV records don't carry EPSS
        "cwes": db_specific.get("cwe_ids") or [],
        "published_at": record.get("published"),
        "source_updated_at": record.get("modified"),
        "withdrawn_at": record.get("withdrawn"),
        "url": _primary_url(record),
    }

    affected = []
    seen_keys = set()  # some records list the same package/range more than once (OSV data quirk);
    # dedupe on exactly the columns the DB's UNIQUE(advisory_id, ecosystem, package_name,
    # vulnerable_range) constraint checks, or a repeated pair crashes the upsert.
    for entry in record.get("affected") or []:
        package = entry.get("package") or {}
        ecosystem = package.get("ecosystem")

        for vuln_range in entry.get("ranges") or []:
            if vuln_range.get("type") == "GIT":
                continue  

            for introduced, fixed in _events_to_intervals(vuln_range.get("events") or []):
                row_ecosystem = ecosystem.lower() if ecosystem else None
                row_package_name = package.get("name")
                row_vulnerable_range = _interval_to_range(introduced, fixed)

                key = (row_ecosystem, row_package_name, row_vulnerable_range)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                affected.append(
                    {
                        "ecosystem": row_ecosystem,
                        "package_name": row_package_name,
                        "vulnerable_range": row_vulnerable_range,
                        "fixed_version": fixed,
                    }
                )

    return advisory, affected
