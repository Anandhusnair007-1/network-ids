"""
tests/test_alert_grouper_and_policy.py
======================================
Automated test suite verifying corrected alert grouping and hybrid decision policies.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from alert_grouper import AlertGrouper
from policy import (
    BaselinePolicy,
    CalibratedThresholdPolicy,
    TieredSeverityPolicy,
)

# ── AlertGrouper Tests ────────────────────────────────────────────────────────

class TestCorrectedAlertGrouper:

    def test_gap_partitioning_without_timestamps(self):
        """
        Critical Test: Ensure unrelated alerts separated by large index gaps
        are NOT globally merged into one monolithic group.
        """
        # Burst 1: Rows 0..5 (6 DDoS flows)
        # Big gap: 100 benign flows (Rows 6..105)
        # Burst 2: Rows 106..112 (7 DDoS flows)
        labels = ["DDoS"] * 6 + ["BENIGN"] * 100 + ["DDoS"] * 7
        sevs = ["HIGH"] * 6 + ["INFO"] * 100 + ["HIGH"] * 7
        df = pd.DataFrame({
            "final_label": labels,
            "severity": sevs,
            "rf_confidence": [0.95] * len(labels),
            "anomaly_score": [-0.1] * len(labels),
        })

        grouper = AlertGrouper(min_alerts=5, max_index_gap=20)
        groups = grouper.group(df)

        # Must produce TWO distinct groups, not one merged group
        assert len(groups) == 2
        assert groups[0].label == "DDoS"
        assert groups[0].count == 6
        assert groups[0].window_start == 0
        assert groups[0].window_end == 5

        assert groups[1].label == "DDoS"
        assert groups[1].count == 7
        assert groups[1].window_start == 106
        assert groups[1].window_end == 112

    def test_burst_below_min_alerts_suppressed(self):
        """A burst with fewer than min_alerts is not emitted."""
        labels = ["DDoS"] * 3 + ["BENIGN"] * 100 + ["PortScan"] * 10
        sevs = ["HIGH"] * 3 + ["INFO"] * 100 + ["HIGH"] * 10
        df = pd.DataFrame({
            "final_label": labels,
            "severity": sevs,
            "rf_confidence": [0.9] * len(labels),
            "anomaly_score": [0.0] * len(labels),
        })
        grouper = AlertGrouper(min_alerts=5, max_index_gap=20)
        groups = grouper.group(df)

        assert len(groups) == 1
        assert groups[0].label == "PortScan"
        assert groups[0].count == 10

    def test_timestamp_based_window_grouping(self):
        """Valid timestamps trigger sliding window grouping."""
        base_time = pd.Timestamp("2026-10-20 10:00:00")
        # 6 flows in minute 1
        ts1 = [base_time + pd.Timedelta(seconds=i * 5) for i in range(6)]
        # 8 flows in minute 10 (gap of 9 minutes)
        ts2 = [base_time + pd.Timedelta(minutes=10, seconds=i * 5) for i in range(8)]

        df = pd.DataFrame({
            "Timestamp": ts1 + ts2,
            "final_label": ["DDoS"] * 14,
            "severity": ["HIGH"] * 14,
            "rf_confidence": [0.98] * 14,
            "anomaly_score": [-0.15] * 14,
        })

        grouper = AlertGrouper(min_alerts=5, window_size=60)
        groups = grouper.group(df)

        assert len(groups) == 2
        assert groups[0].count == 6
        assert groups[1].count == 8

    def test_empty_and_single_row_handling(self):
        grouper = AlertGrouper(min_alerts=5)
        assert grouper.group(pd.DataFrame(columns=["final_label", "severity", "rf_confidence", "anomaly_score"])) == []

        df_single = pd.DataFrame({
            "final_label": ["DDoS"],
            "severity": ["HIGH"],
            "rf_confidence": [0.9],
            "anomaly_score": [-0.1],
        })
        assert grouper.group(df_single) == []


# ── Decision Policy Tests ─────────────────────────────────────────────────────

class TestHybridPolicies:

    def test_baseline_policy_behavior(self):
        policy = BaselinePolicy()
        rf_codes = np.array([0, 1, 0])
        rf_confs = np.array([0.9, 0.95, 0.85])
        rf_labels = np.array(["BENIGN", "DDoS", "BENIGN"], dtype=object)
        if_scores = np.array([0.1, -0.05, -0.2])

        final_labels, severities, is_attack, is_anomaly = policy.evaluate(
            rf_codes, rf_confs, rf_labels, if_scores, base_threshold=0.0
        )
        assert list(final_labels) == ["BENIGN", "DDoS", "Anomaly (Unclassified)"]
        assert list(severities) == ["INFO", "HIGH", "MEDIUM"]
        assert list(is_attack) == [False, True, False]
        assert list(is_anomaly) == [False, False, True]

    def test_calibrated_threshold_policy(self):
        policy = CalibratedThresholdPolicy(target_threshold=-0.1)
        rf_codes = np.array([0, 0])
        rf_confs = np.array([0.9, 0.9])
        rf_labels = np.array(["BENIGN", "BENIGN"], dtype=object)
        # Score -0.05 is above target_threshold (-0.1) -> treated as benign
        # Score -0.15 is below target_threshold (-0.1) -> treated as anomaly
        if_scores = np.array([-0.05, -0.15])

        final_labels, severities, _, is_anom = policy.evaluate(
            rf_codes, rf_confs, rf_labels, if_scores, base_threshold=0.0
        )
        assert list(final_labels) == ["BENIGN", "Anomaly (Unclassified)"]
        assert list(severities) == ["INFO", "MEDIUM"]

    def test_tiered_severity_policy(self):
        policy = TieredSeverityPolicy(deep_threshold=-0.05, marginal_threshold=0.05)
        rf_codes = np.array([0, 0, 0])
        rf_confs = np.array([0.9, 0.9, 0.9])
        rf_labels = np.array(["BENIGN", "BENIGN", "BENIGN"], dtype=object)
        if_scores = np.array([0.1, 0.0, -0.1])

        final_labels, severities, _, is_anom = policy.evaluate(
            rf_codes, rf_confs, rf_labels, if_scores, base_threshold=0.05
        )
        assert severities[0] == "INFO"    # Normal (score > 0.05)
        assert severities[1] == "LOW"     # Marginal anomaly (0.0 <= score < 0.05)
        assert severities[2] == "MEDIUM"  # Deep anomaly (score < -0.05)
