"""SQLAlchemy 2.0 ORM models for the depwatch app database.

Stage 2 tables:
- advisories: one row per source's view of a vulnerability, keyed by (source, source_id).
- affected:   child of advisories, one row per affected package x version range.
The embedding column (Stage 3) holds Qwen3-Embedding-0.6B vectors (1024-dim);
embedded_at drives incremental re-embedding.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    delete,
    func,
    insert,
)
from sqlalchemy.dialects.postgresql import ARRAY, TIMESTAMP
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
)

from depwatch import config


class Base(DeclarativeBase):
    """Declarative base; its .metadata is what Alembic autogenerate reads."""


class Advisory(Base):
    __tablename__ = "advisories"

    id: Mapped[int] = mapped_column(primary_key=True)

    # identity: the pair (source, source_id) is the real-world key (see UNIQUE below)
    source: Mapped[str] = mapped_column(String(20))
    source_id: Mapped[str] = mapped_column(String(128))
    cve_id: Mapped[str | None] = mapped_column(String(32))

    # human-readable (description is what we embed at Stage 3)
    summary: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)

    # how bad
    severity: Mapped[str | None] = mapped_column(String(20))
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    epss_score: Mapped[float | None] = mapped_column(Numeric)
    cwes: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # timeline (the source's own clocks)
    published_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    source_updated_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    withdrawn_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))

    # one verification link
    url: Mapped[str | None] = mapped_column(Text)

    # Stage 3: semantic embedding of the advisory text (Qwen3-0.6B, 1024-dim), plus
    # when it was last embedded (drives incremental re-embedding vs updated_at)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1024))
    embedded_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))

    # our own row bookkeeping (created_at fixed; updated_at refreshed on upsert)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    affected: Mapped[list[Affected]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("source", "source_id", name="uq_advisories_source_id"),
    )


class Affected(Base):
    __tablename__ = "affected"

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[int] = mapped_column(
        ForeignKey("advisories.id", ondelete="CASCADE")
    )

    ecosystem: Mapped[str] = mapped_column(String(50))
    package_name: Mapped[str] = mapped_column(Text)
    vulnerable_range: Mapped[str | None] = mapped_column(Text)
    fixed_version: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )

    advisory: Mapped[Advisory] = relationship(back_populates="affected")

    __table_args__ = (
        UniqueConstraint(
            "advisory_id",
            "ecosystem",
            "package_name",
            "vulnerable_range",
            name="uq_affected_advisory_pkg_range",
        ),
        Index("ix_affected_ecosystem_package", "ecosystem", "package_name"),
    )


# Stage 4 tables: a watched/scanned repo (`projects`) and the dependencies we extract
# from it (`dependencies`). Same parent→child shape as advisories→affected.


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)

    # identity: the repo URL (see UNIQUE below)
    url: Mapped[str] = mapped_column(Text)
    name: Mapped[str | None] = mapped_column(Text)  # owner/repo, derived from the URL
    commit_sha: Mapped[str | None] = mapped_column(String(40))  # the commit we scanned
    last_scanned_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    dependencies: Mapped[list[Dependency]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("url", name="uq_projects_url"),)


class Dependency(Base):
    __tablename__ = "dependencies"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE")
    )

    ecosystem: Mapped[str] = mapped_column(String(50))  # PURL type: npm, pypi, ...
    package_name: Mapped[str] = mapped_column(
        Text
    )  # scoped name, e.g. @alloc/quick-lru
    version: Mapped[str | None] = mapped_column(Text)  # resolved/pinned version
    purl: Mapped[str | None] = mapped_column(Text)  # full PURL, kept for provenance

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )

    project: Mapped[Project] = relationship(back_populates="dependencies")

    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "ecosystem",
            "package_name",
            "version",
            name="uq_dependency_project_pkg_version",
        ),
        Index("ix_dependencies_ecosystem_package", "ecosystem", "package_name"),
    )


# --- app-side DB access: engine, session, writes ---------------------------

_engine = None


def get_engine():
    """Lazily create the app engine from config.database_url() (host vs container aware)."""
    global _engine
    if _engine is None:
        _engine = create_engine(config.database_url())
    return _engine


@contextmanager
def session_scope():
    """Transactional scope: commit on success, roll back on error, always close."""
    session = Session(get_engine())
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


_ADVISORY_KEY = ("source", "source_id")  # the (source, source_id) conflict key


def upsert_advisory(session: Session, advisory: dict, affected: list[dict]) -> None:
    """Idempotently write one advisory + its affected rows. Caller commits.

    Upsert the advisory on (source, source_id); on conflict, refresh the mutable
    fields and bump updated_at. Then replace the advisory's affected rows so a
    changed package list never leaves stale children.
    """
    stmt = pg_insert(Advisory).values(**advisory)
    set_ = {col: stmt.excluded[col] for col in advisory if col not in _ADVISORY_KEY}
    set_["updated_at"] = func.now()
    stmt = stmt.on_conflict_do_update(
        index_elements=list(_ADVISORY_KEY),
        set_=set_,
    ).returning(Advisory.id)
    advisory_id = session.execute(stmt).scalar_one()

    session.execute(delete(Affected).where(Affected.advisory_id == advisory_id))
    if affected:
        session.execute(
            insert(Affected),
            [{**row, "advisory_id": advisory_id} for row in affected],
        )


_PROJECT_KEY = ("url",)  # the project's real-world key


def upsert_project(session: Session, project: dict, dependencies: list[dict]) -> int:
    """Idempotently write one project + its dependencies; return the project id. Caller commits.

    Upsert the project on `url`; on conflict refresh the mutable fields (name, commit_sha,
    last_scanned_at) and bump updated_at. Then replace the project's dependency rows so a
    changed dependency set never leaves stale children. (Same shape as upsert_advisory.)
    """
    stmt = pg_insert(Project).values(**project)
    set_ = {col: stmt.excluded[col] for col in project if col not in _PROJECT_KEY}
    set_["updated_at"] = func.now()
    stmt = stmt.on_conflict_do_update(
        index_elements=list(_PROJECT_KEY),
        set_=set_,
    ).returning(Project.id)
    project_id = session.execute(stmt).scalar_one()

    session.execute(delete(Dependency).where(Dependency.project_id == project_id))
    if dependencies:
        session.execute(
            insert(Dependency),
            [{**dep, "project_id": project_id} for dep in dependencies],
        )
    return project_id
