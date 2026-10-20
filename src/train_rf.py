"""
train_rf.py
===========
Train the supervised Random Forest classifier on the CIC-IDS2017 dataset
(known attack categories only – withheld categories are excluded).

Outputs
-------
    models/rf_model.pkl          – trained RandomForestClassifier
    models/rf_scaler.pkl         – StandardScaler (fit on train split)
    models/rf_eval.json          – precision / recall / macro-F1 / FPR on val set
    data/processed/features.json – authoritative feature list (must match preprocess.py)
"""

from __future__ import annotations

import json
import logging
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import StandardScaler

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

LABEL_COL = "Label"
RANDOM_STATE = 42


def load_features() -> list[str]:
    with open(DATA_DIR / "features.json") as f:
        return json.load(f)


def load_split(name: str, feature_cols: list[str]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (X, y_multiclass, y_binary) for the given split name."""
    df = pd.read_parquet(DATA_DIR / f"{name}.parquet")
    X  = df[feature_cols].to_numpy(dtype=np.float32)
    y_mc = df["label_code"].to_numpy(dtype=np.int32)
    y_bin = df["is_attack"].to_numpy(dtype=np.int32)
    return X, y_mc, y_bin


def false_positive_rate(cm: np.ndarray) -> float:
    """FPR = FP / (FP + TN)  – binary confusion matrix."""
    tn, fp = cm[0, 0], cm[0, 1]
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def main() -> None:
    log.info("=== Random Forest Training ===")

    feature_cols = load_features()
    log.info("Using %d features.", len(feature_cols))

    # -- Load data ------------------------------------------------------------
    X_train, y_train_mc, y_train_bin = load_split("train", feature_cols)
    X_val,   y_val_mc,   y_val_bin   = load_split("val",   feature_cols)
    log.info("Train: %d rows | Val: %d rows", len(X_train), len(X_val))

    # -- Scale ----------------------------------------------------------------
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_val   = scaler.transform(X_val)

    # -- Train ----------------------------------------------------------------
    log.info("Fitting RandomForestClassifier (this may take a few minutes) ...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    clf.fit(X_train, y_train_mc)
    log.info("Training complete.")

    # -- Evaluate on validation set -------------------------------------------
    y_pred_mc  = clf.predict(X_val)
    y_pred_bin = (y_pred_mc != 0).astype(int)   # 0 = BENIGN code

    # Load label map, then build target_names only for classes present in val set
    with open(DATA_DIR / "label_map.json") as f:
        label_map: dict = json.load(f)
    present_codes = sorted(set(y_val_mc.tolist()) | set(y_pred_mc.tolist()))
    target_names  = [label_map.get(str(c), f"Unknown({c})") for c in present_codes]

    report_str = classification_report(
        y_val_mc, y_pred_mc,
        labels=present_codes,
        target_names=target_names,
        zero_division=0
    )
    log.info("Classification report (multiclass):\n%s", report_str)

    macro_f1  = f1_score(y_val_mc, y_pred_mc, average="macro", zero_division=0)
    macro_p   = precision_score(y_val_mc, y_pred_mc, average="macro", zero_division=0)
    macro_r   = recall_score(y_val_mc, y_pred_mc, average="macro", zero_division=0)

    cm_bin = confusion_matrix(y_val_bin, y_pred_bin)
    fpr    = false_positive_rate(cm_bin)

    eval_metrics = {
        "macro_precision": round(float(macro_p), 4),
        "macro_recall":    round(float(macro_r), 4),
        "macro_f1":        round(float(macro_f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "val_rows": int(len(y_val_mc)),
    }
    log.info("Eval metrics: %s", eval_metrics)

    # -- Save artefacts -------------------------------------------------------
    with open(MODELS_DIR / "rf_model.pkl", "wb") as f:
        pickle.dump(clf, f)
    log.info("Saved model -> models/rf_model.pkl")

    with open(MODELS_DIR / "rf_scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    log.info("Saved scaler -> models/rf_scaler.pkl")

    with open(MODELS_DIR / "rf_eval.json", "w") as f:
        json.dump(eval_metrics, f, indent=2)
    log.info("Saved eval metrics -> models/rf_eval.json")

    print("\nValidation Results")
    print("------------------")
    for k, v in eval_metrics.items():
        print(f"  {k:<28} {v}")
    print("\n" + report_str)


if __name__ == "__main__":
    main()
