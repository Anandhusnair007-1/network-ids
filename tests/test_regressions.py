"""
tests/test_regressions.py
=========================
Regression tests for defects found in the project audit:

* SHAP attribution indexed the class axis by label code instead of ``classes_`` position.
* The dashboard inference path dropped Label / Timestamp / IP columns.
* ``predict_df`` applied the 50k upload limit to trusted offline evaluation batches.
* No way to regenerate the SHA-256 manifest after retraining.
* Alert-compression KPI counted un-grouped alerts as "saved".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import security
from alert_grouper import AlertGrouper, groups_to_dataframe, summarize_groups
from config import pretty_label
from explain import baseline_deviation, class_position, shap_attribution
from hybrid import HybridDetector
from policy import POLICY_INFO, TieredSeverityPolicy, build_policy
from validator import OversizedInputError

FEATS = ["a", "b", "c"]


def _detector(n_rows: int = 3) -> HybridDetector:
    rf = MagicMock()
    rf.classes_ = np.array([0, 1, 5])  # gap on purpose: code 5 sits at position 2
    rf.predict_proba.return_value = np.tile([0.1, 0.1, 0.8], (n_rows, 1))
    iforest = MagicMock()
    iforest.decision_function.return_value = np.full(n_rows, 0.2)
    scaler = MagicMock()
    scaler.transform.side_effect = lambda x: x
    return HybridDetector(rf, iforest, scaler, {0: "BENIGN", 1: "DDoS", 5: "PortScan"}, threshold=0.0)


class TestShapClassAxis:
    def test_class_position_uses_classes_not_code(self):
        rf = MagicMock()
        rf.classes_ = np.array([0, 1, 5])
        assert class_position(rf, 5) == 2
        with pytest.raises(KeyError):
            class_position(rf, 9)

    @pytest.mark.parametrize("layout", ["new", "old"])
    def test_attribution_reads_the_right_class_slice(self, layout):
        rf = MagicMock()
        rf.classes_ = np.array([0, 1, 5])
        per_class = {0: [0.0, 0.0, 0.0], 1: [0.0, 0.0, 0.0], 5: [0.3, -0.2, 0.1]}
        explainer = MagicMock()
        if layout == "new":  # shap >= 0.45: (samples, features, classes)
            arr = np.zeros((1, 3, 3))
            arr[0, :, 2] = per_class[5]
            explainer.shap_values.return_value = arr
        else:                # shap < 0.45: list over classes of (samples, features)
            explainer.shap_values.return_value = [np.array([per_class[c]]) for c in (0, 1, 5)]
        out = shap_attribution(explainer, rf, np.zeros((1, 3)), FEATS, class_code=5, top_k=3)
        assert out.iloc[0]["feature"] == "a" and out.iloc[0]["direction"] == "toward class"
        assert out.set_index("feature").loc["b", "shap"] == pytest.approx(-0.2)

    def test_baseline_deviation_handles_zero_variance(self):
        scaler = MagicMock()
        scaler.mean_ = np.array([1.0, 2.0, 3.0])
        scaler.scale_ = np.array([1.0, 0.0, 2.0])
        out = baseline_deviation(scaler, np.array([3.0, 2.0, 3.0]), FEATS, top_k=3)
        assert out.iloc[0]["feature"] == "a" and np.isfinite(out["z_score"]).all()


class TestPredictDf:
    def test_extra_columns_survive(self):
        det = _detector()
        df = pd.DataFrame({"a": [1.0, 2.0, 3.0], "b": 0.0, "c": 0.0, "Label": ["x", "y", "z"],
                           "Timestamp": ["t1", "t2", "t3"], "Source IP": ["1.1.1.1"] * 3})
        out = det.predict_df(df, FEATS)
        assert {"Label", "Timestamp", "Source IP", "severity", "final_label"} <= set(out.columns)

    def test_upload_limit_enforced_but_overridable_for_offline_batches(self):
        det = _detector(n_rows=6)
        df = pd.DataFrame({"a": np.zeros(6), "b": 0.0, "c": 0.0})
        with pytest.raises(OversizedInputError):
            det.predict_df(df, FEATS, max_rows=3)
        assert len(det.predict_df(df, FEATS, max_rows=6)) == 6

    def test_single_forest_pass(self):
        det = _detector()
        det.predict(np.zeros((3, 3), dtype=np.float32))
        det.rf.predict.assert_not_called()           # arg-max over predict_proba replaces predict()
        det.rf.predict_proba.assert_called_once()

    def test_with_policy_shares_models(self):
        det = _detector()
        other = det.with_policy(TieredSeverityPolicy())
        assert other.rf is det.rf and other.iforest is det.iforest and other.policy is not det.policy

    def test_signals_then_apply_policy_matches_predict(self):
        det = _detector()
        labels, sev = det.apply_policy(det.signals(np.zeros((3, 3), dtype=np.float32)))
        assert list(labels) == [r.final_label for r in det.predict(np.zeros((3, 3), dtype=np.float32))]
        assert set(sev) == {"HIGH"}  # RF says PortScan for every row


class TestPolicyRegistry:
    @pytest.mark.parametrize("key", list(POLICY_INFO))
    def test_every_registered_policy_builds_and_evaluates(self, key):
        pol = build_policy(key, 0.06)
        n = 4
        out = pol.evaluate(np.zeros(n, dtype=int), np.full(n, 0.9), np.array(["BENIGN"] * n, dtype=object),
                           np.array([-0.1, 0.0, 0.05, 0.2]), 0.06, 0)
        assert len(out[1]) == n

    def test_unknown_policy_rejected(self):
        with pytest.raises(KeyError):
            build_policy("nope", 0.0)


class TestManifestRegeneration:
    def test_roundtrip_and_tamper_detection(self, tmp_path):
        names = {"m.pkl": "Model", "t.json": "ThresholdConfig"}
        (tmp_path / "m.pkl").write_bytes(b"model-bytes")
        (tmp_path / "t.json").write_text(json.dumps({"threshold": 0.1}))
        manifest_path = tmp_path / "manifest.json"
        security.write_manifest(manifest_path, artifact_types=names)
        assert set(security.verify_all_artifacts(manifest_path)) == set(names)
        (tmp_path / "m.pkl").write_bytes(b"tampered")
        with pytest.raises(security.ArtifactIntegrityError):
            security.verify_all_artifacts(manifest_path)

    def test_refuses_to_register_missing_artifact(self, tmp_path):
        with pytest.raises(security.ArtifactNotFoundError):
            security.write_manifest(tmp_path / "manifest.json", artifact_types={"missing.pkl": "x"})

    def test_repo_manifest_still_valid(self):
        if not (security.MANIFEST_PATH.parent / "rf_model.pkl").exists():
            pytest.skip("model artifacts not present")
        assert len(security.verify_all_artifacts()) == 4


class TestAlertTriageHonesty:
    @staticmethod
    def _alerts(n_dos=8, n_scan=3):
        n = n_dos + n_scan
        return pd.DataFrame({
            "final_label": ["DoS"] * n_dos + ["PortScan"] * n_scan, "severity": "HIGH",
            "rf_confidence": 0.9, "anomaly_score": 0.1, "Source IP": ["a"] * 4 + ["b"] * (n - 4),
            "Destination IP": "d",
        })

    def test_ip_columns_split_incidents(self):
        groups = AlertGrouper(min_alerts=3, max_index_gap=1000).group(self._alerts())
        df = groups_to_dataframe(groups)
        assert {"src_ip", "dst_ip"} <= set(df.columns)
        assert set(df["src_ip"]) <= {"a", "b"}

    def test_ungrouped_alerts_are_not_counted_as_saved(self):
        alerts = self._alerts().drop(columns=["Source IP", "Destination IP"])
        groups = AlertGrouper(min_alerts=5).group(alerts)       # PortScan (3) stays below the minimum
        k = summarize_groups(groups, len(alerts))
        assert k["incidents"] == 1 and k["ungrouped_alerts"] == 3 and k["analyst_queue"] == 4
        assert k["queue_reduction"] == pytest.approx(1 - 4 / 11)

    def test_no_alerts(self):
        assert summarize_groups([], 0)["queue_reduction"] == 0.0


class TestLabelDisplay:
    def test_mojibake_repaired(self):
        assert pretty_label("Web Attack � XSS") == "Web Attack – XSS"
        assert pretty_label("BENIGN") == "BENIGN"
