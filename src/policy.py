"""
src/policy.py
=============
Configurable decision arbitration policies for the Hybrid Network IDS.
Supports baseline triage, calibrated thresholds, tiered severity separation,
and confidence-gated anomaly filtering.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np

try:
    from config import (
        ANOMALY_LABEL,
        BENIGN_LABEL,
        SEVERITY_HIGH,
        SEVERITY_INFO,
        SEVERITY_MEDIUM,
    )
except ImportError:
    from src.config import (
        ANOMALY_LABEL,
        BENIGN_LABEL,
        SEVERITY_HIGH,
        SEVERITY_INFO,
        SEVERITY_MEDIUM,
    )

SEVERITY_LOW = "LOW"
MARGINAL_ANOMALY_LABEL = "Anomaly (Marginal / Low Priority)"


class HybridDecisionPolicy(ABC):
    """Abstract base class for hybrid decision arbitration."""

    @abstractmethod
    def evaluate(
        self,
        rf_codes: np.ndarray,
        rf_confs: np.ndarray,
        rf_labels: np.ndarray,
        if_scores: np.ndarray,
        base_threshold: float,
        benign_code: int = 0,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Evaluate model signals and assign final labels and severities.

        Returns
        -------
        final_labels : np.ndarray (dtype object/str)
        severities   : np.ndarray (dtype object/str)
        is_attack    : np.ndarray (dtype bool)
        is_anomaly   : np.ndarray (dtype bool)
        """


class BaselinePolicy(HybridDecisionPolicy):
    """
    Production baseline policy:
    1. RF says attack -> RF label, HIGH severity.
    2. RF says benign and IF < base_threshold -> Anomaly (Unclassified), MEDIUM severity.
    3. Both benign -> BENIGN, INFO severity.
    """

    def evaluate(
        self,
        rf_codes: np.ndarray,
        rf_confs: np.ndarray,
        rf_labels: np.ndarray,
        if_scores: np.ndarray,
        base_threshold: float,
        benign_code: int = 0,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        is_attack = rf_codes != benign_code
        if_flags = if_scores < base_threshold
        is_anomaly = if_flags & (~is_attack)

        final_labels = np.where(is_attack, rf_labels, np.where(is_anomaly, ANOMALY_LABEL, BENIGN_LABEL))
        severities = np.where(is_attack, SEVERITY_HIGH, np.where(is_anomaly, SEVERITY_MEDIUM, SEVERITY_INFO))

        return final_labels, severities, is_attack, is_anomaly


class CalibratedThresholdPolicy(HybridDecisionPolicy):
    """
    Calibrated policy using a customized anomaly threshold (e.g. t=0.0 or t=-0.03)
    derived from validation data to reduce false-positive rates.
    """

    def __init__(self, target_threshold: float) -> None:
        self.target_threshold = target_threshold

    def evaluate(
        self,
        rf_codes: np.ndarray,
        rf_confs: np.ndarray,
        rf_labels: np.ndarray,
        if_scores: np.ndarray,
        base_threshold: float,
        benign_code: int = 0,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        is_attack = rf_codes != benign_code
        if_flags = if_scores < self.target_threshold
        is_anomaly = if_flags & (~is_attack)

        final_labels = np.where(is_attack, rf_labels, np.where(is_anomaly, ANOMALY_LABEL, BENIGN_LABEL))
        severities = np.where(is_attack, SEVERITY_HIGH, np.where(is_anomaly, SEVERITY_MEDIUM, SEVERITY_INFO))

        return final_labels, severities, is_attack, is_anomaly


class TieredSeverityPolicy(HybridDecisionPolicy):
    """
    Separates anomaly alerts into deep (MEDIUM) and marginal (LOW) severities.
    Allows high-priority queues to stay clean without discarding marginal telemetry:
    - Known attack: HIGH
    - Deep anomaly (score < deep_threshold): MEDIUM
    - Marginal anomaly (deep_threshold <= score < marginal_threshold): LOW
    - Benign: INFO
    """

    def __init__(self, deep_threshold: float = -0.03, marginal_threshold: float = 0.061102) -> None:
        self.deep_threshold = deep_threshold
        self.marginal_threshold = marginal_threshold

    def evaluate(
        self,
        rf_codes: np.ndarray,
        rf_confs: np.ndarray,
        rf_labels: np.ndarray,
        if_scores: np.ndarray,
        base_threshold: float,
        benign_code: int = 0,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        is_attack = rf_codes != benign_code
        is_deep_anomaly = (~is_attack) & (if_scores < self.deep_threshold)
        is_marginal_anomaly = (~is_attack) & (~is_deep_anomaly) & (if_scores < self.marginal_threshold)
        is_anomaly = is_deep_anomaly | is_marginal_anomaly

        final_labels = np.where(
            is_attack,
            rf_labels,
            np.where(
                is_deep_anomaly,
                ANOMALY_LABEL,
                np.where(is_marginal_anomaly, MARGINAL_ANOMALY_LABEL, BENIGN_LABEL),
            ),
        )

        severities = np.where(
            is_attack,
            SEVERITY_HIGH,
            np.where(
                is_deep_anomaly,
                SEVERITY_MEDIUM,
                np.where(is_marginal_anomaly, SEVERITY_LOW, SEVERITY_INFO),
            ),
        )

        return final_labels, severities, is_attack, is_anomaly


class ConfidenceGatedPolicy(HybridDecisionPolicy):
    """
    Experimental policy that suppresses marginal anomalies only when the Random Forest
    is extremely confident (e.g. >99.9%) that the flow is benign, unless the anomaly
    score indicates an extreme deviation.
    """

    def __init__(
        self,
        anomaly_threshold: float = 0.061102,
        confidence_ceiling: float = 0.999,
        deep_threshold: float = -0.05,
    ) -> None:
        self.anomaly_threshold = anomaly_threshold
        self.confidence_ceiling = confidence_ceiling
        self.deep_threshold = deep_threshold

    def evaluate(
        self,
        rf_codes: np.ndarray,
        rf_confs: np.ndarray,
        rf_labels: np.ndarray,
        if_scores: np.ndarray,
        base_threshold: float,
        benign_code: int = 0,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        is_attack = rf_codes != benign_code
        raw_anomaly = (if_scores < self.anomaly_threshold) & (~is_attack)

        # Suppress marginal anomalies only if RF confidence in BENIGN exceeds ceiling
        is_extremely_confident_benign = (rf_codes == benign_code) & (rf_confs >= self.confidence_ceiling)
        is_suppressed = is_extremely_confident_benign & (if_scores >= self.deep_threshold)

        is_anomaly = raw_anomaly & (~is_suppressed)

        final_labels = np.where(is_attack, rf_labels, np.where(is_anomaly, ANOMALY_LABEL, BENIGN_LABEL))
        severities = np.where(is_attack, SEVERITY_HIGH, np.where(is_anomaly, SEVERITY_MEDIUM, SEVERITY_INFO))

        return final_labels, severities, is_attack, is_anomaly


# ---------------------------------------------------------------------------
# Policy registry (single source of truth for CLI, evaluation and dashboard)
# ---------------------------------------------------------------------------
DEEP_ANOMALY_THRESHOLD = -0.03

POLICY_INFO: dict[str, dict[str, str]] = {
    "tiered": {
        "label": "Tiered (recommended)",
        "short": "Tiered",
        "summary": "Known attacks HIGH, deep anomalies MEDIUM, marginal anomalies LOW (hunting queue).",
    },
    "baseline": {
        "label": "Baseline (max recall)",
        "short": "Baseline",
        "summary": "Any anomaly below the validation-tuned threshold is MEDIUM. Highest recall, noisiest.",
    },
    "balanced": {
        "label": "Balanced (t = 0)",
        "short": "Balanced",
        "summary": "Anomaly threshold moved to 0.0 to cut false alarms at some cost to novel-threat recall.",
    },
    "confidence_gated": {
        "label": "Confidence-gated (beta)",
        "short": "Gated",
        "summary": "Suppresses marginal anomalies when the forest is >99.9% sure the flow is benign.",
    },
}


def build_policy(name: str, base_threshold: float) -> HybridDecisionPolicy:
    """Instantiate a policy by registry key. ``base_threshold`` is the detector's tuned IF threshold."""
    if name == "tiered":
        return TieredSeverityPolicy(DEEP_ANOMALY_THRESHOLD, base_threshold)
    if name == "baseline":
        return BaselinePolicy()
    if name == "balanced":
        return CalibratedThresholdPolicy(target_threshold=0.0)
    if name == "confidence_gated":
        return ConfidenceGatedPolicy(anomaly_threshold=base_threshold)
    raise KeyError(f"Unknown policy '{name}'. Valid: {sorted(POLICY_INFO)}")
