"""
preprocess.py
=============
Preprocessing pipeline for the CIC-IDS2017 dataset.

Steps
-----
1.  Load all raw CSVs, strip column names.
2.  Drop infinities, fill remaining NaNs with 0.
3.  Remove exact-duplicate rows.
4.  Map labels -> integer codes; keep a separate binary column (0=BENIGN, 1=ATTACK).
5.  WITHHELD CATEGORIES: two attack families are removed from the
    supervised training split and saved separately for the held-out
    anomaly experiment (Week 6).
6.  Stratified 60/20/20 train/val/test split (known attacks only).
7.  Save artefacts to data/processed/.

Withheld categories (unseen-category experiment)
-------------------------------------------------
    - 'Infiltration'
    - 'Web Attack - Brute Force'
    - 'Web Attack - XSS'
    - 'Web Attack - Sql Injection'
These labels are never seen by the Random Forest during training.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# -- Paths --------------------------------------------------------------------
RAW_DIR  = Path("data/raw/MachineLearningCVE")
OUT_DIR  = Path("data/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# -- Logging ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# -- Constants ----------------------------------------------------------------
LABEL_COL = "Label"
RANDOM_STATE = 42

# Attack categories withheld from supervised training (unseen-category experiment).
# The CSV en-dash (U+2013) is decoded as the UTF-8 replacement character (U+FFFD),
# so we match by prefix/substring rather than exact string.
WITHHELD_PREFIXES: tuple[str, ...] = (
    "Infiltration",
    "Web Attack",   # catches Brute Force, XSS, Sql Injection variants
)


def _is_withheld(label: str) -> bool:
    return any(label.startswith(p) for p in WITHHELD_PREFIXES)

# Columns to drop (non-feature metadata)
DROP_COLS: list[str] = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Timestamp",
]

CHUNKSIZE = 100_000


# -- Helpers ------------------------------------------------------------------

def _load_all_csvs() -> pd.DataFrame:
    """Load and concatenate all raw CSVs."""
    files = sorted(RAW_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {RAW_DIR}")
    log.info("Found %d CSV files in %s", len(files), RAW_DIR)

    frames: list[pd.DataFrame] = []
    for path in files:
        log.info("  Loading %s (%.1f MB) ...", path.name, path.stat().st_size / 1e6)
        chunks: list[pd.DataFrame] = []
        for chunk in pd.read_csv(path, low_memory=False, chunksize=CHUNKSIZE):
            chunk.columns = chunk.columns.str.strip()
            chunks.append(chunk)
        frames.append(pd.concat(chunks, ignore_index=True))

    df = pd.concat(frames, ignore_index=True)
    log.info("Concatenated shape: %s", df.shape)
    return df


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    """Drop metadata columns, fix infinities / NaNs, remove duplicates."""
    # Drop metadata columns that exist
    to_drop = [c for c in DROP_COLS if c in df.columns]
    df = df.drop(columns=to_drop)
    log.info("Dropped metadata columns: %s", to_drop)

    # Normalise label whitespace
    df[LABEL_COL] = df[LABEL_COL].astype(str).str.strip()

    # Replace infinities with NaN, then fill NaN -> 0
    numeric_cols = df.select_dtypes(include="number").columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    missing_before = df.isna().sum().sum()
    df[numeric_cols] = df[numeric_cols].fillna(0)
    log.info("Replaced %d missing/infinite numeric values with 0.", missing_before)

    # Remove exact-duplicate rows
    n_before = len(df)
    df = df.drop_duplicates()
    log.info("Removed %d duplicate rows.", n_before - len(df))

    return df.reset_index(drop=True)


def _encode_labels(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[int, str]]:
    """
    Add two columns:
        label_code  - integer code per attack family (0 = BENIGN)
        is_attack   - binary flag (0 = BENIGN, 1 = ATTACK)

    Returns the modified DataFrame and a code->label mapping dict.
    """
    le = LabelEncoder()
    df["label_code"] = le.fit_transform(df[LABEL_COL])
    df["is_attack"]  = (df[LABEL_COL] != "BENIGN").astype(int)

    code_map: dict[int, str] = {
        int(code): str(label_name)
        for code, label_name in zip(le.transform(le.classes_), le.classes_)
    }
    log.info("Label distribution:\n%s", df[LABEL_COL].value_counts().to_string())
    return df, code_map


def _split_withheld(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Separate rows whose Label starts with any WITHHELD_PREFIXES.
    Returns (known_df, withheld_df).
    """
    mask = df[LABEL_COL].apply(_is_withheld)
    withheld = df[mask].copy()
    known    = df[~mask].copy()
    log.info(
        "Withheld %d rows (%d attack families) for held-out experiment.",
        len(withheld), withheld[LABEL_COL].nunique(),
    )
    log.info(
        "Known-category rows: %d  (BENIGN: %d, Known attacks: %d)",
        len(known),
        (known[LABEL_COL] == "BENIGN").sum(),
        (known[LABEL_COL] != "BENIGN").sum(),
    )
    return known, withheld


def _stratified_split(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """60 / 20 / 20 stratified split on label_code."""
    strat = df["label_code"]

    train, temp = train_test_split(
        df, test_size=0.40, stratify=strat, random_state=RANDOM_STATE
    )
    val, test = train_test_split(
        temp, test_size=0.50, stratify=temp["label_code"], random_state=RANDOM_STATE
    )
    log.info(
        "Split sizes -> train: %d  val: %d  test: %d",
        len(train), len(val), len(test),
    )
    return train, val, test


# -- Main ---------------------------------------------------------------------

def main() -> None:
    log.info("=== CIC-IDS2017 Preprocessing Pipeline ===")

    df = _load_all_csvs()
    df = _clean(df)
    df, code_map = _encode_labels(df)

    known, withheld = _split_withheld(df)

    # Save withheld set (for anomaly evaluation in Week 6)
    withheld_path = OUT_DIR / "withheld.parquet"
    withheld.to_parquet(withheld_path, index=False)
    log.info("Saved withheld rows -> %s", withheld_path)

    # Stratified train / val / test on known categories
    train, val, test = _stratified_split(known)

    train.to_parquet(OUT_DIR / "train.parquet", index=False)
    val.to_parquet(OUT_DIR / "val.parquet",   index=False)
    test.to_parquet(OUT_DIR / "test.parquet",  index=False)
    log.info("Saved train / val / test parquets to %s", OUT_DIR)

    # Save label map for later use by training scripts
    label_map_path = OUT_DIR / "label_map.json"
    with open(label_map_path, "w") as f:
        json.dump(code_map, f, indent=2)
    log.info("Saved label map -> %s", label_map_path)

    # Save feature list (all columns except Label, label_code, is_attack)
    feature_cols = [
        c for c in train.columns
        if c not in (LABEL_COL, "label_code", "is_attack")
    ]
    features_path = OUT_DIR / "features.json"
    with open(features_path, "w") as f:
        json.dump(feature_cols, f, indent=2)
    log.info("Saved %d feature names -> %s", len(feature_cols), features_path)

    log.info("=== Preprocessing complete ===")
    print("\nSummary")
    print("-------")
    print(f"  Total rows processed : {len(df):,}")
    print(f"  Train rows           : {len(train):,}")
    print(f"  Val rows             : {len(val):,}")
    print(f"  Test rows            : {len(test):,}")
    print(f"  Withheld rows        : {len(withheld):,}")
    print(f"  Features             : {len(feature_cols)}")
    print(f"  Outputs in           : {OUT_DIR}/")


if __name__ == "__main__":
    main()
