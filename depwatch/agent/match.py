"""Deterministic vulnerability matching: which of a project's dependencies are actually
exposed to a known advisory — i.e. the installed version falls inside the vulnerable range.

No LLM, no embeddings: one indexed SQL join (dependencies -> affected -> advisories on
package identity) + per-ecosystem version math via `univers`. The candidates this produces
are the input to the LLM triage in 4c.
"""

from __future__ import annotations

import logging

from sqlalchemy import case, select
from sqlalchemy.orm import Session
from univers.version_range import build_range_from_github_advisory_constraint

from depwatch.storage.postgres import Advisory, Affected, Dependency

log = logging.getLogger(__name__)

# Our dependencies.ecosystem is the PURL type (npm, pypi, golang, ...); GHSA's
# affected.ecosystem uses different spellings for some. Map PURL type -> GHSA for the join.
# (PURL types already equal univers' scheme names, so the version math needs no mapping.)
ECOSYSTEM_MAP = {"pypi": "pip", "golang": "go", "cargo": "rust", "gem": "rubygems"}


def to_advisory_ecosystem(purl_type: str) -> str:
    """PURL type (our dependencies) -> GHSA ecosystem spelling (our advisories)."""
    return ECOSYSTEM_MAP.get(purl_type, purl_type)


def version_in_range(scheme: str, version: str, vulnerable_range: str) -> bool | None:
    """Is `version` inside GHSA's `vulnerable_range` for this ecosystem?

    `scheme` is the PURL type / univers scheme (npm, pypi, ...). Returns None if we can't
    parse it (unknown scheme or malformed input) so the caller can log rather than silently
    treat it as safe.
    """
    try:
        rng = build_range_from_github_advisory_constraint(scheme, vulnerable_range)
        return rng.version_class(version) in rng
    except Exception as exc:  # univers raises various errors on unknown scheme / bad input
        log.warning(
            "version_in_range unparseable: scheme=%s version=%r range=%r (%s)",
            scheme, version, vulnerable_range, exc,
        )
        return None


def match_project(session: Session, project_id: int) -> list[dict]:
    """Candidate findings for a project: (dependency, advisory) pairs where the dependency's
    version falls in the advisory's vulnerable range.

    One indexed join gets package-level candidates (dep <-> affected on ecosystem+package),
    then univers filters by version. No persistence — that's 4c's `findings` table.
    """
    # match our PURL-type ecosystem to GHSA's spelling inside the join
    advisory_eco = case(ECOSYSTEM_MAP, value=Dependency.ecosystem, else_=Dependency.ecosystem)

    stmt = (
        select(
            Dependency.id.label("dependency_id"),
            Dependency.ecosystem,
            Dependency.package_name,
            Dependency.version,
            Affected.vulnerable_range,
            Affected.fixed_version,
            Advisory.id.label("advisory_id"),
            Advisory.source_id,
            Advisory.severity,
            Advisory.summary,
        )
        .join(
            Affected,
            (Affected.ecosystem == advisory_eco)
            & (Affected.package_name == Dependency.package_name),
        )
        .join(Advisory, Advisory.id == Affected.advisory_id)
        .where(Dependency.project_id == project_id)
    )

    candidates: list[dict] = []
    for row in session.execute(stmt):
        if not row.vulnerable_range:
            continue
        # row.ecosystem is the PURL type, which equals the univers scheme
        if version_in_range(row.ecosystem, row.version, row.vulnerable_range):
            candidates.append(
                {
                    "dependency_id": row.dependency_id,
                    "ecosystem": row.ecosystem,
                    "package_name": row.package_name,
                    "version": row.version,
                    "advisory_id": row.advisory_id,
                    "advisory": row.source_id,
                    "severity": row.severity,
                    "summary": row.summary,
                    "vulnerable_range": row.vulnerable_range,
                    "fixed_version": row.fixed_version,
                }
            )
    return candidates