"""Extract a repo's dependencies with OSV-SCALIBR (the `scalibr` CLI), then parse its SPDX.

scalibr walks the clone, reads manifests + lockfiles (npm, PyPI, ...), and writes an SPDX
doc where each package carries a PURL (pkg:type/name@version). We parse those PURLs into
{ecosystem, package_name, version, purl}. scalibr only READS files — never executes them.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from packageurl import PackageURL

# Where the scalibr binary lives. Overridable so the Docker image can point elsewhere later.
SCALIBR_BIN = os.environ.get(
    "DEPWATCH_SCALIBR_BIN", os.path.expanduser("~/go/bin/scalibr")
)


def run_scalibr(repo_path: Path) -> dict:
    """Run scalibr over the repo and return the parsed SPDX document."""
    out = Path(tempfile.mkdtemp(prefix="depwatch-spdx-")) / "out.spdx.json"
    subprocess.run(
        [SCALIBR_BIN, "-root", str(repo_path), "-o", f"spdx23-json={out}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(out.read_text())


def parse_spdx(doc: dict) -> list[dict]:
    """SPDX doc -> [{ecosystem, package_name, version, purl}]. Pure (no I/O) -> testable.

    The PURL (not the SPDX `name` field) is authoritative: it carries the ecosystem, the
    full scoped name, and the version. We skip packages with no PURL (the SPDX root node)
    and no version (the repo's own workspace packages), and de-dupe across lockfiles.
    """
    deps: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for pkg in doc.get("packages", []):
        purl_str = next(
            (
                ref["referenceLocator"]
                for ref in pkg.get("externalRefs", [])
                if ref.get("referenceType") == "purl"
            ),
            None,
        )
        if not purl_str:
            continue  # SPDX root/document package has no PURL
        purl = PackageURL.from_string(purl_str)
        name = f"{purl.namespace}/{purl.name}" if purl.namespace else purl.name
        if not name or not purl.version:
            continue  # workspace packages have no version
        key = (purl.type, name, purl.version)
        if key in seen:
            continue  # the same package can appear in multiple lockfiles
        seen.add(key)
        deps.append(
            {
                "ecosystem": purl.type,  # PURL type (npm, pypi, ...); mapped to advisories' spelling in 4b
                "package_name": name,
                "version": purl.version,
                "purl": purl_str,
            }
        )
    return deps


def extract_dependencies(repo_path: Path) -> list[dict]:
    """Run scalibr on the clone and parse its SPDX into dependency dicts."""
    return parse_spdx(run_scalibr(repo_path))
