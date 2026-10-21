"""
src/hybrid.py
=============
Hybrid decision logic combining the Random Forest classifier and the
Isolation Forest anomaly detector.

Decision rules
--------------
1.  RF predicts the label.
2.  IF produces an anomaly score (lower = more anomalous) and a binary flag.
3.  Combined label:
      - If RF says ATTACK -> keep RF label (high confidence).
      - If RF says BENIGN AND IF flags anomaly -> label as "Anomaly (Unclassified)".
      - If both say BENIGN -> BENIGN.
4.  Alert severity:
      - Known attack (RF) -> HIGH
      - Anomaly (IF only) -> MEDIUM
      - BENIGN             -> INFO

Performance & Security
----------------------
- Decision arbitration is fully vectorized via NumPy.
- Pluggable decision policies support tunable false-positive mitigation.
- Cryptographic SHA-256 verification is performed before unpickling any model artifact.
- Telemetry input validation is executed prior to feature scaling.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

try:
    from config import (
        BENIGN_LABEL,
        DATA_DIR,
        MANIFEST_PATH,
        MODELS_DIR,
        VERIFY_INTEGRITY,
    )
    from policy import BaselinePolicy, HybridDecisionPolicy
    from security import safe_load_pickle, verify_artifact_integrity
    from validator import InputValidator
except ImportError:
    from src.config import (
        BENIGN_LABEL,
        DATA_DIR,
        MANIFEST_PATH,
        MODELS_DIR,
        VERIFY_INTEGRITY,
    )
    from src.policy import BaselinePolicy, HybridDecisionPolicy
    from src.security import safe_load_pickle, verify_artifact_integrity
    from src.validator import InputValidator


@dataclass
class HybridResult:
    rf_label:       str
    rf_confidence:  float          # max class probability
    is_anomaly:     bool           # Isolation Forest flag
    anomaly_score:  float          # decision_function value (lower = worse)
    final_label:    str
    severity:       str            # HIGH / MEDIUM / INFO


class HybridDetector:
    """
    Wraps both trained models and applies the hybrid decision logic.

    Parameters
    ----------
    rf_model : Any
        Trained supervised classifier (RandomForestClassifier).
    iforest_model : Any
        Trained unsupervised anomaly detector (IsolationForest).
    scaler : Any
        Fitted feature scaler (StandardScaler).
    label_map : dict[int, str]
        Integer code to class label mapping.
    threshold : float
        Decision threshold for Isolation Forest anomaly scores.
    policy : HybridDecisionPolicy | None
        Decision arbitration policy (defaults to BaselinePolicy).
    """

    def __init__(
        self,
        rf_model,
        iforest_model,
        scaler,
        label_map: dict[int, str],
        threshold: float,
        policy: HybridDecisionPolicy | None = None,
    ) -> None:
        self.rf        = rf_model
        self.iforest   = iforest_model
        self.scaler    = scaler
        self.label_map = label_map
        self.threshold = threshold
        self.policy    = policy if policy is not None else BaselinePolicy()

        # Precompute vectorized label lookup array
        max_code = max(self.label_map.keys()) if self.label_map else 0
        self._label_lookup = np.array(
            [self.label_map.get(i, f"Unknown({i})") for i in range(max_code + 1)],
            dtype=object,
        )
        self._benign_code = next(
            (k for k, v in self.label_map.items() if v == BENIGN_LABEL),
            0,
        )

    # ------------------------------------------------------------------
    @classmethod
    def load(
        cls,
        models_dir: Path = MODELS_DIR,
        data_dir: Path = DATA_DIR,
        manifest_path: Path = MANIFEST_PATH,
        verify_integrity: bool = VERIFY_INTEGRITY,
        policy: HybridDecisionPolicy | None = None,
    ) -> HybridDetector:
        """
        Securely load serialized models and configuration.
        Validates SHA-256 cryptographic hashes before any pickle deserialization.
        """
        rf = safe_load_pickle(
            models_dir / "rf_model.pkl",
            manifest_path=manifest_path,
            verify_integrity=verify_integrity,
        )
        iforest = safe_load_pickle(
            models_dir / "iforest_model.pkl",
            manifest_path=manifest_path,
            verify_integrity=verify_integrity,
        )
        scaler = safe_load_pickle(
            models_dir / "rf_scaler.pkl",
            manifest_path=manifest_path,
            verify_integrity=verify_integrity,
        )

        with open(data_dir / "label_map.json", "r", encoding="utf-8") as f:
            label_map: dict[int, str] = {int(k): v for k, v in json.load(f).items()}

        threshold_path = models_dir / "iforest_threshold.json"
        if verify_integrity:
            verify_artifact_integrity(threshold_path, manifest_path=manifest_path)

        with open(threshold_path, "r", encoding="utf-8") as f:
            threshold = float(json.load(f)["threshold"])

        return cls(rf, iforest, scaler, label_map, threshold, policy=policy)

    # ------------------------------------------------------------------
    def predict(self, X_raw: np.ndarray) -> list[HybridResult]:
        """
        Vectorized prediction returning a list of HybridResult objects.

        Parameters
        ----------
        X_raw : np.ndarray of shape (n_samples, n_features) – UNSCALED.

        Returns
        -------
        List of HybridResult, one per row.
        """
        if len(X_raw) == 0:
            return []

        X = self.scaler.transform(X_raw)

        # Model inferences
        rf_codes   = self.rf.predict(X)
        rf_proba   = self.rf.predict_proba(X)
        rf_confs   = rf_proba.max(axis=1)
        if_scores  = self.iforest.decision_function(X)
        if_flags   = if_scores < self.threshold

        rf_labels = self._label_lookup[rf_codes]

        # Vectorized policy evaluation
        final_labels, severities, _, _ = self.policy.evaluate(
            rf_codes=rf_codes,
            rf_confs=rf_confs,
            rf_labels=rf_labels,
            if_scores=if_scores,
            base_threshold=self.threshold,
            benign_code=self._benign_code,
        )

        results: list[HybridResult] = [
            HybridResult(
                rf_label=str(lbl),
                rf_confidence=float(conf),
                is_anomaly=bool(anom),
                anomaly_score=float(score),
                final_label=str(flbl),
                severity=str(sev),
            )
            for lbl, conf, anom, score, flbl, sev in zip(
                rf_labels, rf_confs, if_flags, if_scores, final_labels, severities
            )
        ]

        return results

    # ------------------------------------------------------------------
    def predict_df(
        self,
        df: pd.DataFrame,
        feature_cols: list[str],
        validate: bool = True,
        fill_missing: bool = False,
    ) -> pd.DataFrame:
        """
        High-throughput vectorized inference wrapper that directly enriches the DataFrame.
        """
        if df.empty:
            out = df.copy()
            for col in ("rf_label", "rf_confidence", "is_anomaly", "anomaly_score", "final_label", "severity"):
                out[col] = pd.Series(dtype=object if "label" in col or "sev" in col else (bool if "is_anom" in col else float))
            return out

        if validate:
            validator = InputValidator(
                feature_cols=feature_cols,
                fill_missing=fill_missing,
                allow_extra_columns=True,
            )
            df_features = validator.validate_df(df)
            X = df_features[feature_cols].to_numpy(dtype=np.float32)
        else:
            X = df[feature_cols].to_numpy(dtype=np.float32)

        X_scaled = self.scaler.transform(X)

        rf_codes   = self.rf.predict(X_scaled)
        rf_proba   = self.rf.predict_proba(X_scaled)
        rf_confs   = rf_proba.max(axis=1)
        if_scores  = self.iforest.decision_function(X_scaled)
        if_flags   = if_scores < self.threshold

        rf_labels = self._label_lookup[rf_codes]

        # Vectorized policy evaluation
        final_labels, severities, _, _ = self.policy.evaluate(
            rf_codes=rf_codes,
            rf_confs=rf_confs,
            rf_labels=rf_labels,
            if_scores=if_scores,
            base_threshold=self.threshold,
            benign_code=self._benign_code,
        )

        out = df.copy()
        out["rf_label"]       = rf_labels
        out["rf_confidence"]  = rf_confs
        out["is_anomaly"]     = if_flags
        out["anomaly_score"]  = if_scores
        out["final_label"]    = final_labels
        out["severity"]       = severities
        return out
