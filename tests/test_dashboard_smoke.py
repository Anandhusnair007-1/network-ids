"""Headless smoke test: the console starts, verifies artifacts and renders the overview."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(not (ROOT / "models" / "rf_model.pkl").exists(), reason="model artifacts not present")
def test_overview_renders_without_errors():
    at = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=120).run()
    assert not at.exception
    assert [t.value for t in at.title] == ["Network intrusion detection"]
    assert at.sidebar.selectbox[0].value == "tiered"
