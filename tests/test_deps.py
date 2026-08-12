"""Unit tests for the SPDX/PURL parser (pure, no scalibr/Docker needed)."""

import json
from pathlib import Path

from depwatch.agent.deps import parse_spdx

FIXTURE = Path(__file__).parent / "fixtures" / "sample.spdx.json"


def test_parse_spdx_normalizes_and_skips():
    doc = json.loads(FIXTURE.read_text())
    deps = parse_spdx(doc)

    got = {(d["ecosystem"], d["package_name"], d["version"]) for d in deps}
    assert got == {
        ("npm", "lodash", "4.17.21"),
        ("npm", "@alloc/quick-lru", "5.2.0"),  # scoped name rejoined + %40 decoded
        ("pypi", "flask", "2.0.1"),
    }

    # root package (no PURL) and workspace package (no version) are skipped;
    # the duplicate lodash is de-duped -> exactly 3 rows.
    assert len(deps) == 3

    # the full PURL is preserved for provenance.
    assert all(d["purl"].startswith("pkg:") for d in deps)
