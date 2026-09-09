"""Unit tests for OSV normalization (depwatch/transform/osv.py).

Pure unit tests: no DB, no MinIO, no network. record_to_rows is tested against real
OSV records (never fabricated — see CLAUDE.md's "never fabricate advisory data"
rule), fetched from https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip
on 2026-09-09. The unused `versions` array (hundreds of entries, not read by
record_to_rows) is trimmed and one long `details` field is truncated for
readability; every field the tests below actually check is real, unmodified data.

The helper functions get their own direct unit tests too, using small synthetic
inputs (named FAKE_ADVISORY_FOR_TESTS_*) for edge cases — multi-interval ranges,
GIT-typed ranges — that would be impractical to hunt down in real data on demand.
"""

import pytest

from depwatch.transform.osv import (
    _cvss_vector,
    _events_to_intervals,
    _find_cve,
    _interval_to_range,
    _primary_url,
    record_to_rows,
)

# Real record: GHSA-mirrored, so it carries severity + database_specific.
GHSA_MIRRORED_RECORD = {
    "schema_version": "1.7.5",
    "id": "GHSA-226f-f24g-524w",
    "published": "2026-06-17T14:10:56Z",
    "modified": "2026-07-13T16:42:55.257503767Z",
    "aliases": ["CVE-2026-54008", "PYSEC-2026-2690"],
    "summary": (
        "Open WebUI: Redirect-Bypass SSRF in OAuth `_process_picture_url` "
        "(incomplete-fix sibling of CVE-2026-45401)"
    ),
    "details": (
        "## Summary\n\n`backend/open_webui/utils/oauth.py::_process_picture_url` "
        "(v0.9.5, lines 1435-1470) calls `validate_url(picture_url)` on the initial "
        "URL only, then invokes `aiohttp.ClientSession.get(picture_url, ...)` "
        "without `allow_redirects=False`. aiohttp's default is `allow_redirects=True, "
        "max_redir ...[truncated for fixture]"
    ),
    "affected": [
        {
            "package": {
                "name": "open-webui",
                "ecosystem": "PyPI",
                "purl": "pkg:pypi/open-webui",
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "0.9.6"}],
                }
            ],
            "database_specific": {
                "last_known_affected_version_range": "<= 0.9.5",
                "source": (
                    "https://github.com/github/advisory-database/blob/main/"
                    "advisories/github-reviewed/2026/06/GHSA-226f-f24g-524w/"
                    "GHSA-226f-f24g-524w.json"
                ),
            },
        }
    ],
    "references": [
        {
            "type": "WEB",
            "url": "https://github.com/open-webui/open-webui/security/advisories/GHSA-226f-f24g-524w",
        },
        {"type": "PACKAGE", "url": "https://github.com/open-webui/open-webui"},
    ],
    "database_specific": {
        "cwe_ids": ["CWE-918"],
        "github_reviewed": True,
        "github_reviewed_at": "2026-06-17T14:10:56Z",
        "nvd_published_at": None,
        "severity": "HIGH",
    },
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"}
    ],
}

# Real record: native PYSEC advisory — no severity, no database_specific, no GHSA mirroring.
PYSEC_NATIVE_RECORD = {
    "schema_version": "1.7.5",
    "id": "PYSEC-2005-1",
    "published": "2005-12-31T05:00:00Z",
    "modified": "2026-06-10T17:02:44.510045829Z",
    "aliases": ["CVE-2005-4644", "GHSA-6vhp-hp77-6w52"],
    "details": (
        "Cross-site scripting (XSS) vulnerability in the HTML WikiProcessor in "
        "Edgewall Trac 0.9.2 allows remote attackers to inject arbitrary web "
        "script or HTML via javascript in the SRC attribute of an IMG tag."
    ),
    "affected": [
        {
            "package": {"name": "trac", "ecosystem": "PyPI", "purl": "pkg:pypi/trac"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "0.10"}],
                }
            ],
            "database_specific": {
                "source": "https://github.com/pypa/advisory-database/blob/main/vulns/trac/PYSEC-2005-1.yaml"
            },
        }
    ],
    "references": [
        {"type": "WEB", "url": "http://projects.edgewall.com/trac/ticket/2473"},
        {"type": "WEB", "url": "http://www.securityfocus.com/bid/16198"},
        {"type": "ADVISORY", "url": "http://secunia.com/advisories/18465"},
        {"type": "ADVISORY", "url": "http://www.debian.org/security/2006/dsa-951"},
        {"type": "ADVISORY", "url": "http://secunia.com/advisories/18555"},
        {"type": "WEB", "url": "http://trac.edgewall.org/ticket/2473"},
        {
            "type": "ADVISORY",
            "url": "http://www.vupen.com/english/advisories/2006/0226",
        },
        {
            "type": "WEB",
            "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/24183",
        },
        {
            "type": "ADVISORY",
            "url": "https://github.com/advisories/GHSA-6vhp-hp77-6w52",
        },
    ],
}


def test_record_to_rows_ghsa_mirrored():
    advisory, affected = record_to_rows(GHSA_MIRRORED_RECORD)

    assert advisory["source"] == "osv"
    assert advisory["source_id"] == "GHSA-226f-f24g-524w"
    assert advisory["cve_id"] == "CVE-2026-54008"
    assert advisory["summary"].startswith("Open WebUI")
    assert advisory["severity"] == "high"
    assert advisory["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"
    assert advisory["cvss_score"] is None
    assert advisory["cwes"] == ["CWE-918"]
    assert advisory["published_at"] == "2026-06-17T14:10:56Z"
    assert advisory["source_updated_at"] == "2026-07-13T16:42:55.257503767Z"
    assert advisory["withdrawn_at"] is None
    assert (
        advisory["url"]
        == "https://github.com/open-webui/open-webui/security/advisories/GHSA-226f-f24g-524w"
    )

    assert affected == [
        {
            "ecosystem": "pypi",
            "package_name": "open-webui",
            "vulnerable_range": "< 0.9.6",
            "fixed_version": "0.9.6",
        }
    ]


def test_record_to_rows_pysec_native_defaults_missing_fields():
    advisory, affected = record_to_rows(PYSEC_NATIVE_RECORD)

    assert advisory["source_id"] == "PYSEC-2005-1"
    assert advisory["cve_id"] == "CVE-2005-4644"
    assert advisory["summary"] is None  # PYSEC records carry no `summary` key at all
    assert advisory["severity"] is None
    assert advisory["cvss_vector"] is None
    assert advisory["cwes"] == []
    assert advisory["url"] == "http://projects.edgewall.com/trac/ticket/2473"

    assert affected == [
        {
            "ecosystem": "pypi",
            "package_name": "trac",
            "vulnerable_range": "< 0.10",
            "fixed_version": "0.10",
        }
    ]


def test_record_to_rows_missing_id_raises():
    FAKE_ADVISORY_FOR_TESTS_NO_ID = {"summary": "malformed record with no id"}
    with pytest.raises(KeyError):
        record_to_rows(FAKE_ADVISORY_FOR_TESTS_NO_ID)


def test_record_to_rows_skips_git_ranges():
    FAKE_ADVISORY_FOR_TESTS_GIT_RANGE = {
        "id": "OSV-TEST-0001",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "example"},
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [{"introduced": "abc123"}, {"fixed": "def456"}],
                    }
                ],
            }
        ],
    }
    _, affected = record_to_rows(FAKE_ADVISORY_FOR_TESTS_GIT_RANGE)
    assert affected == []


def test_record_to_rows_dedupes_identical_affected_rows():
    # Real bug found running load_osv against the live PyPI dump: GHSA-2763-cj5r-c79m
    # lists "praisonai" twice in `affected`, both times with the identical range --
    # violates the DB's UNIQUE(advisory_id, ecosystem, package_name, vulnerable_range)
    # constraint if not deduped here.
    FAKE_ADVISORY_FOR_TESTS_DUPLICATE_PACKAGE = {
        "id": "OSV-TEST-2001",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "praisonai"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "4.5.121"}],
                    }
                ],
            },
            {
                "package": {"ecosystem": "PyPI", "name": "praisonai"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "4.5.121"}],
                    }
                ],
            },
        ],
    }
    _, affected = record_to_rows(FAKE_ADVISORY_FOR_TESTS_DUPLICATE_PACKAGE)
    assert affected == [
        {
            "ecosystem": "pypi",
            "package_name": "praisonai",
            "vulnerable_range": "< 4.5.121",
            "fixed_version": "4.5.121",
        }
    ]


def test_find_cve_picks_first_cve_alias():
    assert _find_cve(["GHSA-x", "CVE-2021-1234", "CVE-2021-9999"]) == "CVE-2021-1234"


def test_find_cve_none_when_no_cve_alias():
    assert _find_cve(["GHSA-aaaa-bbbb-cccc", "PYSEC-2020-1"]) is None


def test_find_cve_none_for_empty_aliases():
    assert _find_cve([]) is None


def test_cvss_vector_prefers_cvss_v3():
    severities = [
        {"type": "CVSS_V4", "score": "CVSS:4.0/FAKE"},
        {"type": "CVSS_V3", "score": "CVSS:3.1/REAL"},
    ]
    assert _cvss_vector(severities) == "CVSS:3.1/REAL"


def test_cvss_vector_falls_back_to_first_when_no_v3():
    severities = [{"type": "CVSS_V2", "score": "AV:N/FAKE"}]
    assert _cvss_vector(severities) == "AV:N/FAKE"


def test_cvss_vector_none_when_empty():
    assert _cvss_vector([]) is None


def test_primary_url_prefers_web_reference():
    record = {
        "id": "OSV-TEST-0002",
        "references": [
            {"type": "PACKAGE", "url": "https://example.com/pkg"},
            {"type": "WEB", "url": "https://example.com/advisory"},
        ],
    }
    assert _primary_url(record) == "https://example.com/advisory"


def test_primary_url_falls_back_to_osv_dev_link():
    record = {
        "id": "OSV-TEST-0003",
        "references": [{"type": "PACKAGE", "url": "https://example.com/pkg"}],
    }
    assert _primary_url(record) == "https://osv.dev/vulnerability/OSV-TEST-0003"


def test_primary_url_falls_back_when_no_references_at_all():
    assert (
        _primary_url({"id": "OSV-TEST-0004"})
        == "https://osv.dev/vulnerability/OSV-TEST-0004"
    )


def test_events_to_intervals_pairs_multiple_disjoint_ranges():
    # a package vulnerable, fixed, then vulnerable again later -- OSV's schema allows this
    events = [
        {"introduced": "0"},
        {"fixed": "1.0"},
        {"introduced": "2.0"},
        {"fixed": "3.0"},
    ]
    assert _events_to_intervals(events) == [("0", "1.0"), ("2.0", "3.0")]


def test_events_to_intervals_open_ended_when_unpatched():
    assert _events_to_intervals([{"introduced": "1.0"}]) == [("1.0", None)]


def test_events_to_intervals_last_affected_closes_like_fixed():
    events = [{"introduced": "1.0"}, {"last_affected": "1.5"}]
    assert _events_to_intervals(events) == [("1.0", "1.5")]


def test_events_to_intervals_empty_events():
    assert _events_to_intervals([]) == []


def test_interval_to_range_drops_zero_lower_bound():
    assert _interval_to_range("0", "2.0.0") == "< 2.0.0"


def test_interval_to_range_keeps_real_lower_bound():
    assert _interval_to_range("1.2.0", "2.0.0") == ">= 1.2.0, < 2.0.0"


def test_interval_to_range_none_when_unbounded_both_sides():
    assert _interval_to_range("0", None) is None
    assert _interval_to_range(None, None) is None
