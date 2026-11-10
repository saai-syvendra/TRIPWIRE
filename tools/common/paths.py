"""
Repo locations. CODE_ROOT holds the schema and skills and never moves. The data roots (samples, scratch,
reports, dataset) are module attributes that tools read at call time as `paths.REPORTS`, never copy, so a test
can point all of them at a temporary folder with one monkeypatch per name.
"""
from __future__ import annotations

from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[2]
SCHEMA = CODE_ROOT / "schema" / "record.schema.json"
REQUIREMENTS = CODE_ROOT / "tools" / "requirements.txt"

ROOT = CODE_ROOT
SAMPLES = ROOT / "samples"
SCRATCH = ROOT / "scratch"
REPORTS = ROOT / "reports"
DATASET = ROOT / "dataset"

DATA_ROOTS = ("SAMPLES", "SCRATCH", "REPORTS", "DATASET")


def point_at(root: Path) -> dict[str, Path]:
    """The data roots as they would be under another repo root (tests use this with monkeypatch)."""
    return {"ROOT": root, **{name: root / name.lower() for name in DATA_ROOTS}}


# Set by tools/analysis/run_analyses.py for a batch session: the one package the session may read.
CONFINE_ENV = "TRIPWIRE_ANALYSIS_KEY"


def confine(path: Path) -> Path:
    """`path`, unless a batch session is confined to one package and the path leaves its scratch folder: then the
    tool refuses, so no command can read another package's (decoded) code or the samples."""
    import os
    key = os.environ.get(CONFINE_ENV)
    if not key:
        return path
    allowed = (SCRATCH / key).resolve()
    if not Path(path).resolve().is_relative_to(allowed):
        raise SystemExit(f"refused: this session may only read scratch/{key}/, not {path}")
    return path
