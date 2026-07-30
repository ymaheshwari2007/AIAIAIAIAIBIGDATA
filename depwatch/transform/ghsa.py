"""Normalize a raw GHSA advisory record into rows for the `advisories` + `affected` tables.

Pure functions only — no DB, no MinIO, no network — so they unit-test with plain pytest.
Target columns live in depwatch/storage/postgres.py. Timestamps pass through as ISO
strings; Postgres casts them to timestamptz on insert.
"""

SOURCE = "github"


def record_to_rows(record: dict) -> tuple[dict, list[dict]]:
    """Map one GHSA advisory record to (advisory, affected).

    advisory: dict keyed by `advisories` columns. Omits id/created_at/updated_at —
      the DB default and the upsert own those.
    affected: one dict per affected package x version range, keyed by `affected`
      columns, WITHOUT advisory_id — the loader fills that in after the advisory is
      upserted and we know its id.
    """
    # cvss/epss are sometimes absent or null -> default to {} so .get() below is safe
    cvss = record.get("cvss") or {}
    epss = record.get("epss") or {}
    severity = record.get("severity")

    advisory = {
        "source": SOURCE,
        "source_id": record["ghsa_id"],  # required; a missing id means a broken record
        "cve_id": record.get("cve_id"),
        "summary": record.get("summary"),
        "description": record.get("description"),
        "severity": severity.lower() if severity else None,
        "cvss_score": cvss.get("score"),
        "cvss_vector": cvss.get("vector_string"),
        "epss_score": epss.get("percentage"),
        "cwes": [cwe["cwe_id"] for cwe in record.get("cwes") or []],
        "published_at": record.get("published_at"),
        "source_updated_at": record.get("updated_at"),
        "withdrawn_at": record.get("withdrawn_at"),
        "url": record.get("html_url"),
    }

    affected = []
    for vuln in record.get("vulnerabilities") or []:
        package = vuln.get("package") or {}
        ecosystem = package.get("ecosystem")
        affected.append(
            {
                "ecosystem": ecosystem.lower() if ecosystem else None,
                "package_name": package.get("name"),
                "vulnerable_range": vuln.get("vulnerable_version_range"),
                "fixed_version": vuln.get("first_patched_version"),
            }
        )

    return advisory, affected