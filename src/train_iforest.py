"""
train_iforest.py
================
Train the Isolation Forest anomaly detector on BENIGN training rows only.

The anomaly threshold is chosen on the VALIDATION split (not the test set)
to avoid data leakage.

Outputs
-------
    models/iforest_model.pkl     – trained IsolationForest
    models/iforest_threshold.json – chosen decision threshold (anomaly score)
    models/iforest_eval.json     – precision / recall / F1 on validation set
"""

from __future__ import annotations

import json
import logging
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)

# -- Paths --------------------------------------------------------------------
DATA_DIR   = Path("data/processed")
MODELS_DIR = Path("models")
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# -- Logging ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

RANDOM_STATE  = 42
CONTAMINATION = 0.05   # conservative: ~5% of training rows expected anomalous


def load_scaler():
    with open(MODELS_DIR / "rf_scaler.pkl", "rb") as f:
        return pickle.load(f)


def load_features() -> list[str]:
    with open(DATA_DIR / "features.json") as f:
        return json.load(f)


def main() -> None:
    log.info("=== Isolation Forest Training ===")

    feature_cols = load_features()
    scaler       = load_scaler()

    # -- Load train (BENIGN only) and full validation split -------------------
    train_df = pd.read_parquet(DATA_DIR / "train.parquet")
    val_df   = pd.read_parquet(DATA_DIR / "val.parquet")

    benign_mask = train_df["Label"] == "BENIGN"
    X_train_benign = scaler.transform(
        train_df.loc[benign_mask, feature_cols].to_numpy(dtype=np.float32)
    )
    log.info("Training Isolation Forest on %d BENIGN rows …", len(X_train_benign))

    X_val  = scaler.transform(val_df[feature_cols].to_numpy(dtype=np.float32))
    y_val  = val_df["is_attack"].to_numpy(dtype=np.int32)   # 0=BENIGN, 1=ATTACK

    # -- Train ----------------------------------------------------------------
    iforest = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    iforest.fit(X_train_benign)
    log.info("Training complete.")

    # -- Choose threshold on validation set -----------------------------------
    # decision_function: lower score = more anomalous
    val_scores = iforest.decision_function(X_val)   # shape (n,)
    # iforest.predict: -1 = anomaly, +1 = normal
    # We sweep thresholds to find best F1 on validation
    best_f1    = -1.0
    best_thresh = float(val_scores.min())

    for pct in np.linspace(1, 20, 40):
        t   = float(np.percentile(val_scores, pct))
        yhat = (val_scores < t).astype(int)   # 1 = anomaly
        f1  = f1_score(y_val, yhat, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = t

    log.info("Best threshold: %.5f  (val F1=%.4f)", best_thresh, best_f1)

    # -- Evaluate with best threshold -----------------------------------------
    y_pred = (val_scores < best_thresh).astype(int)
    prec   = precision_score(y_val, y_pred, zero_division=0)
    rec    = recall_score(y_val, y_pred, zero_division=0)
    f1     = f1_score(y_val, y_pred, zero_division=0)

    report = classification_report(
        y_val, y_pred, target_names=["BENIGN", "ATTACK"], zero_division=0
    )
    log.info("Isolation Forest val report:\n%s", report)

    eval_metrics = {
        "precision":  round(float(prec), 4),
        "recall":     round(float(rec), 4),
        "f1":         round(float(f1), 4),
        "threshold":  round(float(best_thresh), 6),
        "val_rows":   len(y_val),
    }

    # -- Save artefacts -------------------------------------------------------
    with open(MODELS_DIR / "iforest_model.pkl", "wb") as f:
        pickle.dump(iforest, f)
    log.info("Saved -> models/iforest_model.pkl")

    with open(MODELS_DIR / "iforest_threshold.json", "w") as f:
        json.dump({"threshold": best_thresh}, f, indent=2)
    log.info("Saved -> models/iforest_threshold.json")

    with open(MODELS_DIR / "iforest_eval.json", "w") as f:
        json.dump(eval_metrics, f, indent=2)
    log.info("Saved -> models/iforest_eval.json")

    print("\nIsolation Forest Validation Results")
    print("------------------------------------")
    for k, v in eval_metrics.items():
        print(f"  {k:<28} {v}")
    print("\n" + report)


if __name__ == "__main__":
    main()
