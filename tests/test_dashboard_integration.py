"""
tests/test_dashboard_integration.py
===================================
Integration tests verifying dashboard operational policy selection,
strict schema validation, DoS safety boundaries, and alert triage integration.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "dashboard"))

from alert_grouper import AlertGrouper, groups_to_dataframe
from config import DATA_DIR
from hybrid import HybridDetector
from policy import (
    BaselinePolicy,
    CalibratedThresholdPolicy,
    TieredSeverityPolicy,
)
from validator import (
    InputValidator,
    MissingFeatureError,
    OversizedInputError,
)


@pytest.fixture(scope="module")
def canonical_features() -> list[str]:
    with open(DATA_DIR / "features.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def test_sample() -> pd.DataFrame:
    df = pd.read_parquet(DATA_DIR / "test.parquet")
    return df.head(100).copy()


# ── Policy Selection Integration Tests ────────────────────────────────────────

class TestDashboardPolicyIntegration:

    def test_baseline_policy_prediction(self, canonical_features, test_sample):
        """Baseline policy produces HIGH, MEDIUM, and INFO severities."""
        detector = HybridDetector.load(policy=BaselinePolicy())
        results = detector.predict_df(test_sample, canonical_features)

        severities = set(results["severity"].unique())
        # Severities must be subset of HIGH, MEDIUM, INFO
        assert severities.issubset({"HIGH", "MEDIUM", "INFO"})
        assert "final_label" in results.columns
        assert "anomaly_score" in results.columns

    def test_tiered_severity_policy_prediction(self, canonical_features, test_sample):
        """Tiered policy introduces LOW severity for marginal anomalies."""
        policy = TieredSeverityPolicy(deep_threshold=-0.03, marginal_threshold=0.061102)
        detector = HybridDetector.load(policy=policy)
        results = detector.predict_df(test_sample, canonical_features)

        severities = set(results["severity"].unique())
        # Severities may include LOW, MEDIUM, HIGH, INFO
        assert severities.issubset({"HIGH", "MEDIUM", "LOW", "INFO"})
        assert len(results) == len(test_sample)

    def test_balanced_policy_threshold(self, canonical_features, test_sample):
        """Balanced policy applies customized threshold (t=0.0)."""
        policy = CalibratedThresholdPolicy(target_threshold=0.0)
        detector = HybridDetector.load(policy=policy)
        results = detector.predict_df(test_sample, canonical_features)

        assert len(results) == len(test_sample)
        # Any row labeled Anomaly (Unclassified) must have score < 0.0
        anomaly_mask = results["final_label"] == "Anomaly (Unclassified)"
        if anomaly_mask.any():
            assert (results.loc[anomaly_mask, "anomaly_score"] < 0.0).all()


# ── Schema Validation & Upload Safety Integration Tests ───────────────────────

class TestUploadValidationIntegration:

    def test_upload_rejection_on_missing_features(self, canonical_features, test_sample):
        """Uploaded DataFrame missing required features must be rejected."""
        corrupted = test_sample.drop(columns=[canonical_features[0], canonical_features[1]])
        validator = InputValidator(feature_cols=canonical_features, fill_missing=False)

        with pytest.raises(MissingFeatureError) as exc_info:
            validator.validate_df(corrupted)
        assert canonical_features[0] in str(exc_info.value)

    def test_upload_fallback_zero_fill_mode(self, canonical_features, test_sample):
        """When fallback mode is enabled, missing features are imputed cleanly."""
        corrupted = test_sample.drop(columns=[canonical_features[0]])
        validator = InputValidator(feature_cols=canonical_features, fill_missing=True)

        clean = validator.validate_df(corrupted)
        assert canonical_features[0] in clean.columns
        assert (clean[canonical_features[0]] == 0.0).all()
        assert len(clean) == len(test_sample)

    def test_oversized_upload_rejection(self, canonical_features):
        """Exceeding max row limit triggers OversizedInputError to prevent DoS."""
        validator = InputValidator(feature_cols=canonical_features, max_rows=50)
        huge_df = pd.DataFrame(np.zeros((60, len(canonical_features))), columns=canonical_features)

        with pytest.raises(OversizedInputError):
            validator.validate_df(huge_df)


# ── Alert Triage Integration Tests ────────────────────────────────────────────

class TestAlertTriageIntegration:

    def test_alert_triage_grouping_on_real_predictions(self, canonical_features, test_sample):
        detector = HybridDetector.load(policy=BaselinePolicy())
        results = detector.predict_df(test_sample, canonical_features)

        # Filter alerts
        alert_flows = results[results["severity"].isin(["HIGH", "MEDIUM"])]
        grouper = AlertGrouper(min_alerts=3, max_index_gap=50, include_benign=False)
        groups = grouper.group(alert_flows)
        groups_df = groups_to_dataframe(groups)

        assert isinstance(groups_df, pd.DataFrame)
        if not groups_df.empty:
            assert "Threat Label" not in groups_df.columns  # before rename
            assert "label" in groups_df.columns
            assert "severity" in groups_df.columns
            assert "count" in groups_df.columns
