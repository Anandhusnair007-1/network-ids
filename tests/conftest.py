"""Skip tests that need trained models / processed data when those artifacts are absent (e.g. a fresh CI checkout)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from config import DATA_DIR, MODELS_DIR  # noqa: E402

ARTIFACT_TESTS = {"test_dashboard_integration.py", "test_dashboard_smoke.py"}


def _have_artifacts() -> bool:
    return (MODELS_DIR / "rf_model.pkl").exists() and (DATA_DIR / "features.json").exists()


def pytest_collection_modifyitems(config, items):
    if _have_artifacts():
        return
    skip = pytest.mark.skip(reason="trained models / processed data not present (run `make all`)")
    for item in items:
        if Path(str(item.fspath)).name in ARTIFACT_TESTS:
            item.add_marker(skip)
