# Network IDS — Hybrid ML Intrusion Detection System
**Minor Project 21CSA391A · Anandhu S Nair**

## What is this?
A hybrid machine-learning Network IDS evaluated on the public CIC-IDS2017 dataset.

| Component | Algorithm | Purpose |
|---|---|---|
| Supervised Classifier | Random Forest (200 trees) | Detect known attacks by family |
| Anomaly Detector | Isolation Forest | Flag traffic never seen in training |
| Explainability | SHAP TreeExplainer | Explain per-flow RF decisions |
| Dashboard | Streamlit | Visualise predictions and alerts |

## Quick Start

```bash
# 1. Install dependencies
make install

# 2. Preprocess raw CSVs -> data/processed/
make preprocess

# 3. Train the Random Forest
make train-rf

# 4. Train the Isolation Forest (requires step 2 & 3)
make train-iforest

# 5. Run held-out category evaluation
make evaluate

# 6. Launch dashboard
make dashboard

# Run all steps 2-5 in sequence
make all
```

## Project Structure
```
network-ids/
├── data/
│   ├── raw/MachineLearningCVE/   ← CIC-IDS2017 CSVs (8 files, ~885 MB)
│   └── processed/                ← train/val/test parquets + label_map.json
├── src/
│   ├── audit_dataset.py          ← Data quality audit
│   ├── preprocess.py             ← Cleaning, splitting, withheld categories
│   ├── train_rf.py               ← Random Forest training
│   ├── train_iforest.py          ← Isolation Forest training
│   ├── hybrid.py                 ← HybridDetector class
│   ├── evaluate_hybrid.py        ← RF vs Hybrid comparison + withheld experiment
│   └── alert_grouper.py          ← Alert grouping / triage
├── dashboard/
│   └── app.py                    ← 5-page Streamlit dashboard
├── models/                       ← Saved .pkl models + JSON metrics
├── reports/                      ← eval_results.json
└── tests/
    └── test_hybrid.py            ← Unit tests (pytest)
```

## Withheld-Category Experiment
The following attack families are **never shown to the Random Forest** during training.
They are held out to test whether the Isolation Forest can flag unseen traffic patterns:

- `Infiltration` (36 flows in Thursday-PM)
- `Web Attack – Brute Force` (1,507 flows)
- `Web Attack – XSS` (652 flows)
- `Web Attack – Sql Injection` (21 flows)

## Dataset
CIC-IDS2017 · University of New Brunswick
> Iman Sharafaldin, Arash Habibi Lashkari, Ali A. Ghorbani,
> "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization",
> ICISSP 2018.

## Tools
Python · Pandas · NumPy · scikit-learn · SHAP · Streamlit · Matplotlib
