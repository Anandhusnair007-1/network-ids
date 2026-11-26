"""
src/service.py
==============
The one scoring pipeline shared by the API, the folder ingestor and any future consumer:

    validate -> score (both models, once) -> apply policy -> persist alerts -> export to SIEM -> drift

Keeping this in one place means every entry point gets identical validation, limits and audit trail.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

import drift  # noqa: E402
from config import (  # noqa: E402
    DB_PATH,
    DEFAULT_POLICY,
    DRIFT_REFERENCE_PATH,
    MAX_UPLOAD_ROWS,
    SINK_MIN_SEVERITY,
    SYSLOG_ADDR,
    WEBHOOK_SECRET,
    WEBHOOK_URL,
    pretty_label,
)
from hybrid import HybridDetector  # noqa: E402
from policy import POLICY_INFO, build_policy  # noqa: E402
from sinks import SinkManager  # noqa: E402
from store import IncidentStore  # noqa: E402
from validator import InputValidator  # noqa: E402

log = logging.getLogger("ids.service")


@dataclass
class ScoreOutcome:
    results: pd.DataFrame
    summary: dict
    batch_id: str | None
    alert_ids: list[str]
    drift: dict | None


class ScoringService:
    def __init__(
        self,
        detector: HybridDetector,
        feature_cols: list[str],
        store: IncidentStore,
        sinks: SinkManager | None = None,
        default_policy: str = "tiered",
        drift_reference: dict | None = None,
    ) -> None:
        if default_policy not in POLICY_INFO:
            raise ValueError(f"Unknown policy '{default_policy}'. Valid: {sorted(POLICY_INFO)}")
        self.base = detector
        self.features = feature_cols
        self.store = store
        self.sinks = sinks or SinkManager()
        self.default_policy = default_policy
        self.drift_reference = drift_reference
        self.scored_total = 0
        self.alerts_total = 0

    @classmethod
    def from_config(cls) -> ScoringService:
        import json

        from config import DATA_DIR

        detector = HybridDetector.load()          # verifies SHA-256 (and signature, if configured) first
        features = json.loads((DATA_DIR / "features.json").read_text(encoding="utf-8"))
        return cls(
            detector,
            features,
            IncidentStore(DB_PATH),
            SinkManager.from_config(WEBHOOK_URL, WEBHOOK_SECRET, SYSLOG_ADDR, SINK_MIN_SEVERITY),
            DEFAULT_POLICY,
            drift.load_reference(DRIFT_REFERENCE_PATH),
        )

    # ------------------------------------------------------------------
    def score(
        self,
        df: pd.DataFrame,
        source: str,
        policy: str | None = None,
        persist: bool = True,
        notify: bool = True,
        fill_missing: bool = False,
        max_rows: int = MAX_UPLOAD_ROWS,
    ) -> ScoreOutcome:
        key = policy or self.default_policy
        detector = self.base.with_policy(build_policy(key, self.base.threshold))   # KeyError on unknown policy

        clean = InputValidator(self.features, max_rows=max_rows, fill_missing=fill_missing).validate_df(df)
        if clean.empty:
            return ScoreOutcome(pd.DataFrame(), {"flows": 0, "alerts": 0, "by_severity": {}}, None, [], None)

        sig = detector.signals(detector.scaler.transform(clean.to_numpy(dtype=np.float32)))
        labels, severities = detector.apply_policy(sig)

        meta = df.reset_index(drop=True).drop(columns=[c for c in self.features if c in df.columns], errors="ignore")
        res = pd.concat([meta, clean.reset_index(drop=True)], axis=1)
        res["rf_label"] = [pretty_label(x) for x in sig["rf_labels"]]
        res["rf_confidence"] = sig["rf_confs"]
        res["anomaly_score"] = sig["if_scores"]
        res["final_label"] = [pretty_label(x) for x in labels]
        res["severity"] = severities

        by_sev = res["severity"].value_counts().to_dict()
        n_alerts = int((res["severity"] != "INFO").sum())
        summary = {
            "flows": int(len(res)),
            "alerts": n_alerts,
            "policy": key,
            "by_severity": {s: int(by_sev.get(s, 0)) for s in ("HIGH", "MEDIUM", "LOW", "INFO")},
            "top_labels": res.loc[res["severity"] != "INFO", "final_label"].value_counts().head(5).to_dict(),
        }

        batch_id, alert_ids = None, []
        if persist:
            batch_id, alert_ids = self.store.save_batch(res, source, key, self.features)
            summary["batch_id"] = batch_id
            if notify and alert_ids:
                self._notify(res, alert_ids)

        drift_report = None
        if self.drift_reference is not None:
            drift_report = drift.assess(self.drift_reference, res, res["anomaly_score"].to_numpy())

        self.scored_total += len(res)
        self.alerts_total += n_alerts
        return ScoreOutcome(res, summary, batch_id, alert_ids, drift_report)

    # ------------------------------------------------------------------
    def _notify(self, res: pd.DataFrame, alert_ids: list[str]) -> None:
        alerts = res[res["severity"] != "INFO"]
        src = next((c for c in ("Source IP", "Src IP", "src_ip") if c in res.columns), None)
        dst = next((c for c in ("Destination IP", "Dst IP", "dst_ip") if c in res.columns), None)
        payload = [
            {
                "alert_id": aid,
                "severity": r["severity"],
                "final_label": r["final_label"],
                "rf_label": r["rf_label"],
                "rf_confidence": round(float(r["rf_confidence"]), 4),
                "anomaly_score": round(float(r["anomaly_score"]), 4),
                "src_ip": str(r[src]) if src else None,
                "dst_ip": str(r[dst]) if dst else None,
            }
            for aid, (_, r) in zip(alert_ids, alerts.iterrows())
        ]
        self.sinks.dispatch(payload)
