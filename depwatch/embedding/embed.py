"""Embed advisory text with Qwen3-Embedding-0.6B (local, via sentence-transformers).

The model is loaded once (lazy singleton) and reused. `embed_texts()` is the only
thing that touches the model; the embed job (`embed_new`) uses it plus the DB.
"""

from __future__ import annotations
from datetime import datetime, timezone

import torch
from sentence_transformers import SentenceTransformer
from sqlalchemy import select, update

from depwatch.storage.postgres import session_scope, Advisory

MODEL_NAME = "Qwen/Qwen3-Embedding-0.6B"
EMBED_DIM = 1024

_model: SentenceTransformer | None = None


def get_model() -> SentenceTransformer:
    """Load the model once and reuse it. Downloads ~1.2GB on the first call.

    Uses Apple Metal (mps) when available, else CPU — so it also runs on a server.
    """
    global _model
    if _model is None:
        device = "mps" if torch.backends.mps.is_available() else "cpu"
        _model = SentenceTransformer(MODEL_NAME, device=device)
        # cap sequence length: advisory text fits well under 512 tokens, and this keeps
        # GPU memory bounded — attention cost grows with seq_len^2, and a few very long
        # descriptions were OOM-ing Metal at the model's huge default limit (~32k).
        _model.max_seq_length = 512
    return _model


def embed_texts(texts: list[str]) -> list[list[float]]:
    """Embed a batch of texts -> a list of 1024-dim vectors (normalized for cosine)."""
    vectors = get_model().encode(texts, batch_size=32, normalize_embeddings=True)
    return vectors.tolist()

def embed_new(batch_size:int = 200) -> int:
  total = 0
  while True:
    with session_scope() as session:
      rows = session.execute(
        select(Advisory.id,Advisory.summary, Advisory.description)
        .where (
          (Advisory.embedding.is_(None)) | (Advisory.updated_at > Advisory.embedded_at)
        ).limit(batch_size)
      ).all()

      if not rows:
        return total
      
      texts = [f"{s or ''}\n{d or ''}" for _id, s, d in rows]
      vectors = embed_texts(texts)
      now = datetime.now(timezone.utc)
      session.execute(
          update(Advisory),
          [
              {"id": row.id, "embedding": vec, "embedded_at": now}
              for row, vec in zip(rows, vectors)
          ],
      )
      total += len(rows)


if __name__ == "__main__":
    # Entry point for the host embed subprocess: run the incremental embed and print
    # the count as JSON so the launcher can return it. Loads the model, embeds on the
    # GPU, writes to Postgres, then this process exits — freeing the ~2-3GB.
    import json

    print(json.dumps({"embedded": embed_new()}))

