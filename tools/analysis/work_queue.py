"""
scratch/queue.jsonl, the batch queue: prepare.py --batch merges rows into it, run_analyses.py works through it and
records each package's outcome in its row. One JSON object per line, keyed by `key` (rows for samples that failed
before their package was identified have `key: null` and are told apart by `sample`).

Every read-modify-write holds an exclusive lock (scratch/queue.lock, flock, plus a thread lock for the parallel
jobs of one process) and replaces the file atomically (temp file + rename), so concurrent writers never lose or
tear a row. Not a command.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
import threading
from pathlib import Path

from tools.common import paths

_THREADS = threading.Lock()


def queue_path() -> Path:
    return paths.SCRATCH / "queue.jsonl"


def read(path: Path | None = None) -> list[dict]:
    """The queue's rows; unreadable lines are dropped."""
    path = path or queue_path()
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def write(rows: list[dict], path: Path | None = None) -> None:
    path = path or queue_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".queue.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


@contextlib.contextmanager
def locked(path: Path | None = None):
    """Exclusive access to the queue for one read-modify-write."""
    path = path or queue_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _THREADS, open(path.with_suffix(".lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield path
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def update(change, path: Path | None = None) -> list[dict]:
    """Applies change(rows) -> rows under the lock and writes the result back."""
    with locked(path) as p:
        rows = change(read(p))
        write(rows, p)
        return rows


def set_fields(key: str, fields: dict, path: Path | None = None) -> list[dict]:
    """Updates the row of `key` with `fields`."""
    def change(rows):
        for r in rows:
            if r.get("key") == key:
                r.update(fields)
        return rows
    return update(change, path)
