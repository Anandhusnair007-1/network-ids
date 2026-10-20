"""
evaluate_hybrid.py
==================
Week 6 experiment: evaluate the hybrid detector on:
  1.  The held-out test split (known attack categories).
  2.  The withheld attack categories (Web Attacks + Infiltration).

Reports
-------
  - Hybrid vs. RF-only comparison table
  - How many withheld-category attacks the anomaly detector catches
  - All results saved to reports/eval_results.json
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

# Add src to path so hybrid.py is importable when run from project root
sys.path.insert(0, str(Path("src")))
from hybrid import HybridDetector  # noqa: E402

# -- Paths --------------------------------------------------------------------
DATA_DIR    = Path("data/processed")
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def fpr(cm: np.ndarray) -> float:
    tn, fp = cm[0, 0], cm[0, 1]
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def eval_binary(y_true, y_pred_bin, label: str) -> dict:
    cm  = confusion_matrix(y_true, y_pred_bin, labels=[0, 1])
    return {
        "label":     label,
        "precision": round(float(precision_score(y_true, y_pred_bin, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_true, y_pred_bin, zero_division=0)), 4),
        "f1":        round(float(f1_score(y_true, y_pred_bin, zero_division=0)), 4),
        "fpr":       round(float(fpr(cm)), 4),
        "n_rows":    int(len(y_true)),
        "n_alerts":  int(y_pred_bin.sum()),
    }


def main() -> None:
    log.info("=== Hybrid Evaluation ===")

    detector = HybridDetector.load()

    with open(DATA_DIR / "features.json") as f:
        feature_cols: list[str] = json.load(f)

    # -------------------------------------------------------------------------
    # 1.  Test split (known attacks)
    # -------------------------------------------------------------------------
    test_df = pd.read_parquet(DATA_DIR / "test.parquet")
    results_test = detector.predict_df(test_df, feature_cols)

    y_true_bin_test  = test_df["is_attack"].to_numpy()
    y_rf_bin_test    = (results_test["rf_label"] != "BENIGN").astype(int).to_numpy()
    y_hyb_bin_test   = (results_test["final_label"] != "BENIGN").astype(int).to_numpy()

    rf_eval    = eval_binary(y_true_bin_test, y_rf_bin_test,  "RF-only (test)")
    hybrid_eval = eval_binary(y_true_bin_test, y_hyb_bin_test, "Hybrid  (test)")

    log.info("RF-only  test  -> %s", rf_eval)
    log.info("Hybrid   test  -> %s", hybrid_eval)

    # Per-class report
    report_test = classification_report(
        test_df["label_code"],
        pd.Categorical(results_test["rf_label"]).codes,
        zero_division=0,
    )

    # -------------------------------------------------------------------------
    # 2.  Withheld categories (unseen-category experiment)
    # -------------------------------------------------------------------------
    withheld_df = pd.read_parquet(DATA_DIR / "withheld.parquet")
    log.info(
        "Withheld label distribution:\n%s",
        withheld_df["Label"].value_counts().to_string(),
    )

    results_w = detector.predict_df(withheld_df, feature_cols)

    total_w    = len(withheld_df)
    rf_caught  = int((results_w["rf_label"] != "BENIGN").sum())
    if_caught  = int(results_w["is_anomaly"].sum())
    hyb_caught = int((results_w["final_label"] != "BENIGN").sum())

    withheld_summary = {
        "total_withheld_rows":   total_w,
        "rf_detected":           rf_caught,
        "if_detected":           if_caught,
        "hybrid_detected":       hyb_caught,
        "rf_detection_rate":     round(rf_caught  / total_w, 4),
        "if_detection_rate":     round(if_caught  / total_w, 4),
        "hybrid_detection_rate": round(hyb_caught / total_w, 4),
        "per_label": {
            label: {
                "total":        int(cnt),
                "rf_detected":  int((results_w.loc[withheld_df["Label"] == label, "rf_label"] != "BENIGN").sum()),
                "if_detected":  int(results_w.loc[withheld_df["Label"] == label, "is_anomaly"].sum()),
            }
            for label, cnt in withheld_df["Label"].value_counts().items()
        }
    }

    # -------------------------------------------------------------------------
    # 3.  Save results
    # -------------------------------------------------------------------------
    all_results = {
        "known_attack_test": {
            "rf_only": rf_eval,
            "hybrid":  hybrid_eval,
        },
        "withheld_experiment": withheld_summary,
    }

    out_path = REPORTS_DIR / "eval_results.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    log.info("Saved evaluation results -> %s", out_path)

    # -------------------------------------------------------------------------
    # 4.  Print summary
    # -------------------------------------------------------------------------
    print("\n========================================")
    print("  HYBRID vs RF-ONLY — KNOWN ATTACKS")
    print("========================================")
    print(f"{'Metric':<20} {'RF-only':>10} {'Hybrid':>10}")
    print("-" * 42)
    for key in ("precision", "recall", "f1", "fpr", "n_alerts"):
        print(f"  {key:<18} {rf_eval[key]:>10} {hybrid_eval[key]:>10}")

    print("\n========================================")
    print("  WITHHELD CATEGORY EXPERIMENT")
    print("========================================")
    print(f"  Total withheld rows     : {total_w:,}")
    print(f"  RF detection rate       : {withheld_summary['rf_detection_rate']:.1%}")
    print(f"  IF detection rate       : {withheld_summary['if_detection_rate']:.1%}")
    print(f"  Hybrid detection rate   : {withheld_summary['hybrid_detection_rate']:.1%}")
    print("\n  Per-label breakdown:")
    for lbl, stats in withheld_summary["per_label"].items():
        print(
            f"    {lbl:<40}  total={stats['total']:>5}"
            f"  rf={stats['rf_detected']:>5}  if={stats['if_detected']:>5}"
        )

    print(f"\nFull results saved to {out_path}")


if __name__ == "__main__":
    main()
