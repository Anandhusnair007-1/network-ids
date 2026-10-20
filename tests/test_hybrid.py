"""
tests/test_hybrid.py
====================
Unit tests for the hybrid detection logic and alert grouper.
Run with: pytest tests/
"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest

# Make src importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from alert_grouper import AlertGrouper, groups_to_dataframe
from hybrid import HybridDetector, HybridResult


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def dummy_label_map() -> dict[int, str]:
    return {0: "BENIGN", 1: "DDoS", 2: "PortScan"}


@pytest.fixture()
def mock_rf(dummy_label_map):
    rf = MagicMock()
    rf.predict.return_value = np.array([0, 1, 0])    # BENIGN, DDoS, BENIGN
    rf.predict_proba.return_value = np.array([
        [0.9, 0.05, 0.05],
        [0.05, 0.9, 0.05],
        [0.8, 0.1, 0.1],
    ])
    rf.classes_ = np.array([0, 1, 2])
    return rf


@pytest.fixture()
def mock_iforest():
    iforest = MagicMock()
    # Row 0: normal, Row 1: normal, Row 2: anomaly
    iforest.decision_function.return_value = np.array([0.1, 0.05, -0.3])
    return iforest


@pytest.fixture()
def mock_scaler():
    scaler = MagicMock()
    scaler.transform.side_effect = lambda x: x   # identity
    return scaler


@pytest.fixture()
def detector(mock_rf, mock_iforest, mock_scaler, dummy_label_map) -> HybridDetector:
    return HybridDetector(
        rf_model=mock_rf,
        iforest_model=mock_iforest,
        scaler=mock_scaler,
        label_map=dummy_label_map,
        threshold=-0.2,   # Row 2 score (-0.3) < threshold -> anomaly
    )


# ── Hybrid logic tests ────────────────────────────────────────────────────────

class TestHybridDetector:

    def test_predict_returns_correct_count(self, detector):
        X = np.zeros((3, 5), dtype=np.float32)
        results = detector.predict(X)
        assert len(results) == 3

    def test_known_attack_is_high(self, detector):
        """Row 1: RF says DDoS -> HIGH severity, final_label = DDoS"""
        X = np.zeros((3, 5), dtype=np.float32)
        results = detector.predict(X)
        assert results[1].final_label == "DDoS"
        assert results[1].severity == "HIGH"

    def test_benign_rf_anomaly_if_is_medium(self, detector):
        """Row 2: RF says BENIGN but IF flags -> MEDIUM, Anomaly label"""
        X = np.zeros((3, 5), dtype=np.float32)
        results = detector.predict(X)
        assert results[2].is_anomaly is True
        assert results[2].severity == "MEDIUM"
        assert "Anomaly" in results[2].final_label

    def test_both_benign_is_info(self, detector):
        """Row 0: RF=BENIGN, IF=normal -> INFO"""
        X = np.zeros((3, 5), dtype=np.float32)
        results = detector.predict(X)
        assert results[0].final_label == "BENIGN"
        assert results[0].severity == "INFO"

    def test_predict_df_adds_columns(self, detector):
        df = pd.DataFrame(np.zeros((3, 5)), columns=[f"f{i}" for i in range(5)])
        out = detector.predict_df(df, [f"f{i}" for i in range(5)])
        for col in ("final_label", "severity", "rf_label", "rf_confidence",
                    "is_anomaly", "anomaly_score"):
            assert col in out.columns


# ── AlertGrouper tests ────────────────────────────────────────────────────────

class TestAlertGrouper:

    def _make_pred_df(self, labels, severities) -> pd.DataFrame:
        n = len(labels)
        return pd.DataFrame({
            "final_label":   labels,
            "severity":      severities,
            "rf_confidence": np.ones(n) * 0.9,
            "anomaly_score": np.ones(n) * -0.1,
        })

    def test_no_group_below_min(self):
        df = self._make_pred_df(["DDoS"] * 3, ["HIGH"] * 3)
        grouper = AlertGrouper(min_alerts=5)
        groups  = grouper.group(df)
        assert len(groups) == 0

    def test_single_group_above_min(self):
        df = self._make_pred_df(["DDoS"] * 10, ["HIGH"] * 10)
        grouper = AlertGrouper(min_alerts=5)
        groups  = grouper.group(df)
        assert len(groups) == 1
        assert groups[0].label == "DDoS"
        assert groups[0].severity == "HIGH"
        assert groups[0].count == 10

    def test_groups_to_dataframe(self):
        df = self._make_pred_df(["PortScan"] * 20, ["HIGH"] * 20)
        grouper = AlertGrouper(min_alerts=5)
        groups  = grouper.group(df)
        gdf = groups_to_dataframe(groups)
        assert isinstance(gdf, pd.DataFrame)
        assert len(gdf) == 1
        assert "label" in gdf.columns

    def test_multiple_groups(self):
        labels = ["DDoS"] * 10 + ["Anomaly (Unclassified)"] * 8
        sevs   = ["HIGH"] * 10 + ["MEDIUM"] * 8
        df = self._make_pred_df(labels, sevs)
        grouper = AlertGrouper(min_alerts=5)
        groups  = grouper.group(df)
        assert len(groups) == 2

    def test_empty_dataframe(self):
        df = self._make_pred_df([], [])
        grouper = AlertGrouper(min_alerts=5)
        groups  = grouper.group(df)
        assert groups == []
