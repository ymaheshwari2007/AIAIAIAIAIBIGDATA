"""Semantic retrieval over the advisory embeddings — the "R" in RAG.

Given a query (and optionally a specific package), embed the query and return the
most relevant advisories by vector distance. This is what the Stage 4 agent calls.
Reuses the model (embed.py) and the DB session (postgres.py) — no new engine.
"""

from __future__ import annotations

from sqlalchemy import select

from depwatch.embedding.embed import embed_texts
from depwatch.storage.postgres import Advisory, Affected, session_scope

# Qwen3 embeds documents plain, but wants an instruction on the QUERY side.
QUERY_TASK = (
    "Given a security concern or dependency, retrieve the most relevant "
    "vulnerability advisories"
)


def embed_query(query: str) -> list[float]:
    """Embed a search query with Qwen3's instruction prefix (docs were embedded plain)."""
    return embed_texts([f"Instruct: {QUERY_TASK}\nQuery: {query}"])[0]


def search(
    query: str,
    k: int = 10,
    ecosystem: str | None = None,
    package: str | None = None,
) -> list[dict]:
    """Return the k most relevant advisories for a query.

    No package        -> pure semantic search over all advisories.
    ecosystem+package -> first restrict to advisories affecting that package, then
                         rank those by relevance ("are we affected, and which matters most?").
    """
    qvec = embed_query(query)
    distance = Advisory.embedding.cosine_distance(
        qvec
    )  # build once, use in select + order

    with session_scope() as session:
        stmt = select(
            Advisory.source_id,
            Advisory.cve_id,
            Advisory.severity,
            Advisory.cvss_score,
            Advisory.summary,
            distance.label("distance"),
        ).where(Advisory.embedding.is_not(None))

        if ecosystem and package:
            stmt = stmt.where(
                Advisory.id.in_(
                    select(Affected.advisory_id).where(
                        Affected.ecosystem == ecosystem.lower(),
                        Affected.package_name == package,
                    )
                )
            )

        stmt = stmt.order_by(distance).limit(k)
        return [dict(row._mapping) for row in session.execute(stmt)]
