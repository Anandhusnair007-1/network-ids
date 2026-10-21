from pathlib import Path

import numpy as np
import pandas as pd

DATA_DIR = Path("data/raw/MachineLearningCVE")
files = sorted(DATA_DIR.glob("*.csv"))

if not files:
    raise SystemExit(f"No CSV files found in {DATA_DIR}")

print(f"Found {len(files)} CSV files\n")

for path in files:
    print("=" * 75)
    print(f"FILE: {path.name}")
    print(f"SIZE: {path.stat().st_size / (1024**2):.1f} MB")

    # Read the complete label column in chunks.
    label_counts = {}
    total_rows = 0
    total_missing_labels = 0
    total_duplicate_rows_in_chunks = 0
    total_missing_cells = 0
    total_infinite_values = 0
    columns = None

    try:
        for chunk in pd.read_csv(
            path,
            low_memory=False,
            chunksize=50000
        ):
            chunk.columns = chunk.columns.str.strip()
            columns = chunk.columns.tolist()
            total_rows += len(chunk)

            label_col = next(
                (c for c in chunk.columns if c.lower() == "label"),
                None
            )
            if label_col is None:
                raise ValueError("No Label column found")

            counts = chunk[label_col].value_counts(dropna=False)
            for label, count in counts.items():
                key = str(label)
                label_counts[key] = label_counts.get(key, 0) + int(count)

            total_missing_labels += int(chunk[label_col].isna().sum())
            total_missing_cells += int(chunk.isna().sum().sum())

            numeric = chunk.select_dtypes(include="number")
            if not numeric.empty:
                total_infinite_values += int(
                    np.isinf(numeric.to_numpy()).sum()
                )

        print(f"\nTotal rows: {total_rows:,}")
        print(f"Columns: {len(columns) if columns else 0}")
        print(f"Missing cells: {total_missing_cells:,}")
        print(f"Missing labels: {total_missing_labels:,}")
        print(f"Infinite numeric values: {total_infinite_values:,}")
        print("\nComplete label counts:")
        for label, count in sorted(
            label_counts.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            print(f"  {label}: {count:,}")

        print("\nFirst 10 columns:")
        print(columns[:10] if columns else [])

    except Exception as exc:
        print(f"ERROR while auditing {path.name}: {exc}")

print("\nFull dataset audit completed.")
print("Raw CSV files were not modified.")
