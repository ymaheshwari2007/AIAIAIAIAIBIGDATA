"""hnsw index on advisories.embedding

Revision ID: 43c9f0a95612
Revises: 502c5084a4e0
Create Date: 2026-08-04 14:22:38.885604

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "43c9f0a95612"
down_revision: Union[str, Sequence[str], None] = "502c5084a4e0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # HNSW index for fast approximate nearest-neighbor search on the embedding column.
    # vector_cosine_ops matches our normalized vectors + the cosine_distance in retrieve.py.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_advisories_embedding_hnsw "
        "ON advisories USING hnsw (embedding vector_cosine_ops)"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP INDEX IF EXISTS ix_advisories_embedding_hnsw")
