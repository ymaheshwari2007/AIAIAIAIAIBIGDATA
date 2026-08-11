"""pgvector embedding on advisories

Revision ID: 502c5084a4e0
Revises: 6ec38f936a6a
Create Date: 2026-08-01 15:04:11.999030

"""

from typing import Sequence, Union

import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "502c5084a4e0"
down_revision: Union[str, Sequence[str], None] = "6ec38f936a6a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # turn on pgvector first — the vector type below needs the extension to exist
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    # nullable: existing rows just get embedding = NULL until the embed job runs
    op.add_column("advisories", sa.Column("embedding", Vector(1024), nullable=True))
    op.add_column(
        "advisories",
        sa.Column("embedded_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("advisories", "embedded_at")
    op.drop_column("advisories", "embedding")
    # leave the `vector` extension installed (harmless, and other things may use it)
