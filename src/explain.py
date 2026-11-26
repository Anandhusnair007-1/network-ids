"""
src/explain.py
==============
Analyst-facing explanations for individual flows.

Two complementary views, because the hybrid raises alerts for two different reasons:

1. ``shap_attribution``   - why the Random Forest chose its class (supervised evidence).
2. ``baseline_deviation`` - how far each feature sits from the training baseline, in standard
   deviations. This is the honest explanation for *anomaly-only* alerts, where the forest says
   BENIGN and the Isolation Forest is the component that fired.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def class_position(rf, class_code: int) -> int:
    """Position of ``class_code`` on the SHAP class axis (``rf.classes_`` order, NOT the code itself)."""
    matches = np.flatnonzero(np.asarray(rf.classes_) == class_code)
    if matches.size == 0:
        raise KeyError(f"Class code {class_code} is not known to the classifier.")
    return int(matches[0])


def _slice_for_class(shap_values, position: int, n_features: int) -> np.ndarray:
    """Return the (n_features,) attribution vector for one sample/class across SHAP API versions."""
    if isinstance(shap_values, list):               # shap < 0.45: list[class] -> (n, features)
        return np.asarray(shap_values[position])[0]
    arr = np.asarray(shap_values)
    if arr.ndim == 3:                               # shap >= 0.45: (n, features, classes)
        return arr[0, :, position]
    if arr.ndim == 2 and arr.shape[1] == n_features:  # binary / single-output model
        return arr[0]
    raise ValueError(f"Unexpected SHAP output shape {arr.shape}")


def make_explainer(rf):
    """Build a TreeExplainer (expensive for 200 deep trees - callers should cache it)."""
    import shap

    return shap.TreeExplainer(rf)


def shap_attribution(
    explainer,
    rf,
    x_scaled_row: np.ndarray,
    feature_cols: list[str],
    class_code: int,
    top_k: int = 15,
) -> pd.DataFrame:
    """
    Signed SHAP attributions for one scaled row toward ``class_code``.

    Positive values push the forest *toward* that class, negative values push away.
    """
    x = np.asarray(x_scaled_row, dtype=np.float32).reshape(1, -1)
    values = explainer.shap_values(x, check_additivity=False)
    vec = _slice_for_class(values, class_position(rf, class_code), len(feature_cols))
    df = pd.DataFrame({"feature": feature_cols, "shap": vec.astype(float)})
    df["abs_shap"] = df["shap"].abs()
    df = df.nlargest(top_k, "abs_shap").reset_index(drop=True)
    df["direction"] = np.where(df["shap"] >= 0, "toward class", "away from class")
    return df[["feature", "shap", "direction"]]


def baseline_deviation(
    scaler,
    x_raw_row: np.ndarray,
    feature_cols: list[str],
    top_k: int = 15,
) -> pd.DataFrame:
    """Per-feature z-score of one raw row against the scaler's training mean/std."""
    x = np.asarray(x_raw_row, dtype=np.float64).reshape(-1)
    mean = np.asarray(scaler.mean_, dtype=np.float64)
    scale = np.where(np.asarray(scaler.scale_, dtype=np.float64) == 0, 1.0, scaler.scale_)
    z = (x - mean) / scale
    df = pd.DataFrame({
        "feature": feature_cols,
        "value": x,
        "baseline_mean": mean,
        "z_score": z,
    })
    df["abs_z"] = df["z_score"].abs()
    return df.nlargest(top_k, "abs_z").drop(columns="abs_z").reset_index(drop=True)
