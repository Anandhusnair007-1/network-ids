"""
src/drift.py
============
Data-drift monitoring with the Population Stability Index (PSI).

A model trained on 2017 lab traffic will degrade silently as your network changes. This module
compares each scored batch with a stored reference distribution (quantile bins per feature, plus the
anomaly-score distribution) and reports which features moved.

Rule of thumb for PSI per feature: < 0.10 stable, 0.10-0.25 moderate shift, > 0.25 significant shift.
The overall status is a heuristic (share of features shifting); treat it as a prompt to investigate,
not as proof the model is wrong. Batches under ``MIN_ROWS`` are reported as "insufficient data".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

MIN_ROWS = 200
EPS = 1e-4
PSI_MODERATE, PSI_SIGNIFICANT = 0.10, 0.25


def _bin_props(values: np.ndarray, edges: np.ndarray) -> np.ndarray:
    idx = np.searchsorted(edges, values, side="right")
    counts = np.bincount(idx, minlength=len(edges) + 1).astype(float)
    return counts / max(counts.sum(), 1.0)


def _edges(values: np.ndarray, n_bins: int) -> np.ndarray:
    qs = np.quantile(values, np.linspace(0, 1, n_bins + 1)[1:-1])
    return np.unique(qs)


def psi(ref_props: np.ndarray, cur_props: np.ndarray) -> float:
    r = np.clip(ref_props, EPS, None)
    c = np.clip(cur_props, EPS, None)
    return float(np.sum((c - r) * np.log(c / r)))


def build_reference(
    df: pd.DataFrame,
    feature_cols: list[str],
    scores: np.ndarray | None = None,
    n_bins: int = 10,
) -> dict[str, Any]:
    """Create the JSON-serialisable reference from a representative sample."""
    ref: dict[str, Any] = {"n_ref": int(len(df)), "n_bins": n_bins, "features": {}}
    for col in feature_cols:
        vals = df[col].to_numpy(dtype=float)
        edges = _edges(vals, n_bins)
        if len(edges) == 0:  # constant feature: nothing to compare
            continue
        ref["features"][col] = {"edges": edges.tolist(), "props": _bin_props(vals, edges).tolist()}
    if scores is not None:
        edges = _edges(np.asarray(scores, dtype=float), n_bins)
        ref["score"] = {"edges": edges.tolist(), "props": _bin_props(np.asarray(scores), edges).tolist()}
    return ref


def save_reference(ref: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ref), encoding="utf-8")


def load_reference(path: Path) -> dict[str, Any] | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def assess(
    ref: dict[str, Any],
    df: pd.DataFrame,
    scores: np.ndarray | None = None,
    top_k: int = 10,
) -> dict[str, Any]:
    """Compare a batch with the reference."""
    n = len(df)
    if n < MIN_ROWS:
        return {"status": "insufficient_data", "n_rows": n, "min_rows": MIN_ROWS}

    per_feature: dict[str, float] = {}
    for col, spec in ref["features"].items():
        if col not in df.columns:
            continue
        edges = np.asarray(spec["edges"], dtype=float)
        cur = _bin_props(df[col].to_numpy(dtype=float), edges)
        per_feature[col] = psi(np.asarray(spec["props"], dtype=float), cur)

    vals = np.array(list(per_feature.values())) if per_feature else np.array([0.0])
    share_sig = float((vals > PSI_SIGNIFICANT).mean())
    share_mod = float((vals > PSI_MODERATE).mean())
    status = "significant" if share_sig >= 0.10 else "moderate" if share_mod >= 0.10 else "stable"

    out: dict[str, Any] = {
        "status": status,
        "n_rows": n,
        "median_psi": float(np.median(vals)),
        "share_features_significant": share_sig,
        "share_features_moderate_or_worse": share_mod,
        "top_drifted": [
            {"feature": k, "psi": round(v, 4)}
            for k, v in sorted(per_feature.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
        ],
    }
    if scores is not None and "score" in ref:
        edges = np.asarray(ref["score"]["edges"], dtype=float)
        out["score_psi"] = psi(np.asarray(ref["score"]["props"], dtype=float), _bin_props(np.asarray(scores), edges))
    return out
