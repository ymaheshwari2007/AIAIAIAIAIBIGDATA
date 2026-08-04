"""Tiny host-side embed launcher (runs on your Mac, NOT in a container).

Stays running at ~tens of MB (no model loaded). When the Airflow embed task POSTs
/embed, it spawns a short-lived subprocess that loads Qwen3 on the GPU, embeds the
advisories that need it, writes them to Postgres, and exits — so the ~2-3GB model
only lives during the run, never while idle.

Run it on your Mac:
    uvicorn depwatch.embedding.service:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import json
import subprocess
import sys

from fastapi import FastAPI, HTTPException

app = FastAPI(title="DepWatch embed launcher")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/embed")
def embed() -> dict:
    # Spawn a fresh process so torch + the model load HERE and are freed on exit.
    proc = subprocess.run(
        [sys.executable, "-m", "depwatch.embedding.embed"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=proc.stderr[-2000:])
    return json.loads(proc.stdout.strip().splitlines()[-1])