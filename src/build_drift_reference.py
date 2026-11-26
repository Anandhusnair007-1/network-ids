"""
Build models/drift_reference.json from the validation split (what the models were tuned on).

    python src/build_drift_reference.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

import drift  # noqa: E402
from config import DATA_DIR, DRIFT_REFERENCE_PATH  # noqa: E402
from hybrid import HybridDetector  # noqa: E402


def main() -> None:
    feats = json.loads((DATA_DIR / "features.json").read_text(encoding="utf-8"))
    val = pd.read_parquet(DATA_DIR / "val.parquet")
    sample = val.sample(min(100_000, len(val)), random_state=42)
    det = HybridDetector.load()
    scores = det.iforest.decision_function(det.scaler.transform(sample[feats].to_numpy(dtype=np.float32)))
    ref = drift.build_reference(sample, feats, scores)
    drift.save_reference(ref, DRIFT_REFERENCE_PATH)
    print(f"Drift reference ({ref['n_ref']:,} rows, {len(ref['features'])} features) -> {DRIFT_REFERENCE_PATH}")


if __name__ == "__main__":
    main()
