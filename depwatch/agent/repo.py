"""Fetch a repo's files for scanning: a shallow, read-only clone. Never executes repo code."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


def clone_repo(url: str, dest: Path | None = None) -> tuple[Path, str]:
    """Shallow, read-only clone of `url`. Returns (clone_path, commit_sha).

    --depth 1: only the latest commit (we scan a snapshot, not the history).
    --no-recurse-submodules: don't pull submodules (untrusted, and not needed).
    We only ever READ the cloned files; nothing from the repo is executed.
    """
    dest = dest or Path(tempfile.mkdtemp(prefix="depwatch-scan-"))
    subprocess.run(
        ["git", "clone", "--depth", "1", "--no-recurse-submodules", url, str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )
    sha = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return dest, sha
