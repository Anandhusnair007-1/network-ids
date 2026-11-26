# 03 — Machine Learning Implementation

**Location:** `/home/anandhu/projects/network-ids/src/train_rf.py`, `/home/anandhu/projects/network-ids/src/train_iforest.py`, `/home/anandhu/projects/network-ids/models/`

---

## 1. Model Artifacts & Cryptographic Verification

Live execution of `.venv/bin/python3 src/security.py` during this audit confirmed all 4 registered artifacts exist on disk and match `models/manifest.json`:

| Artifact | Type | Disk Size | SHA-256 Prefix | Verified in Audit |
| :--- | :--- | :---: | :--- | :--- |
| `models/rf_model.pkl` | `RandomForestClassifier` | 79 MB (`82,180,752` B) | `d56190eeb2b761d9...` | Yes (`security.py` OK) |
| `models/rf_scaler.pkl` | `StandardScaler` | 2.3 KB (`2,297` B) | `1aa1ddf0280fcc9c...` | Yes (`security.py` OK; `pickletools` confirmed `sklearn 1.9.1`) |
| `models/iforest_model.pkl` | `IsolationForest` | 1.4 MB (`1,459,943` B) | `cce40a8d45a58551...` | Yes (`security.py` OK) |
| `models/iforest_threshold.json` | `ThresholdConfig` | 38 B | `ee1d824598a003fd...` | Yes (`security.py` OK; `threshold = 0.06110182785930004`) |

Additional model-directory files: `models/rf_eval.json`, `models/iforest_eval.json`, and `models/drift_reference.json` (12 KB).

---

## 2. Supervised Random Forest Classifier (`src/train_rf.py`)

- **Architecture & Hyperparameters (`L91–97`):**
  - `sklearn.ensemble.RandomForestClassifier`
  - `n_estimators = 200`
  - `max_depth = None` (unpruned trees, explaining 79 MB serialized size)
  - `class_weight = "balanced"` (inversely proportional class weighting for imbalanced attack families)
  - `n_jobs = -1`
  - `random_state = 42`
- **Preprocessing / Scaling (`L85–87`):**
  - `sklearn.preprocessing.StandardScaler` fit on `train.parquet` (78 `float32` features), then applied to `val.parquet` (and at inference time in `HybridDetector`).
- **Target Classes (`data/processed/label_map.json`):**
  - Trained on **11 known classes** (codes `0`–`8`, `10`, `11` — `BENIGN`, `Bot`, `DDoS`, `DoS GoldenEye`, `DoS Hulk`, `DoS Slowhttptest`, `DoS slowloris`, `FTP-Patator`, `Heartbleed`, `PortScan`, `SSH-Patator`). Codes `9` (`Infiltration`) and `12`–`14` (`Web Attack` variants) are absent from `train.parquet`, creating a gap in `rf.classes_`.
- **Persistence (`L136–146`):**
  - Saved with `pickle.dump` to `models/rf_model.pkl` and `models/rf_scaler.pkl`; validation metrics written to `models/rf_eval.json`.
- **Prediction Implementation (`src/hybrid.py` L182–193):**
  - Single-pass optimization: calls `self.rf.predict_proba(X_scaled)` once, obtains predicted class codes via `classes[rf_proba.argmax(axis=1)]` (with fallback to `rf.predict()` for test doubles), and extracts `rf_confs = rf_proba.max(axis=1)`.
- **Recorded Validation Results (`models/rf_eval.json`, `val_rows = 504,037`):**
  - `macro_precision`: **0.9371**
  - `macro_recall`: **0.9961**
  - `macro_f1`: **0.9530**
  - `false_positive_rate` (binary): **0.0026** (0.26%)

*(Note: `TECHNICAL_PROJECT_REPORT.md` Section 11.1 reports test-split multiclass metrics of Macro Precision = 0.9065, Macro Recall = 0.9951, Macro F1 = 0.9345; `eval_results.json` stores binary test metrics and policy comparisons rather than the per-class table.)*

---

## 3. Unsupervised / Semi-Supervised Isolation Forest (`src/train_iforest.py`)

- **Training Data Selection (`L72–76`):**
  - Filters `train.parquet` strictly to `Label == "BENIGN"` (**1,257,890 rows**), scaled using the already-fitted `rf_scaler.pkl`. No attack flows are used to fit Isolation Forest.
- **Model Configuration (`L82–88`):**
  - `sklearn.ensemble.IsolationForest`
  - `n_estimators = 200`
  - `contamination = 0.05` (used by sklearn for `.predict()`, though overridden operationally by the validation-calibrated threshold)
  - `random_state = 42`, `n_jobs = -1`
- **Anomaly Scoring (`L93`):**
  - Uses `iforest.decision_function(X_scaled)` where **lower scores indicate greater anomaly** (shifted path-length score).
- **Threshold Calibration (`L96–105`):**
  - Sweeps 40 linearly spaced percentiles (`np.linspace(1, 20, 40)`) of `val_scores` on the independent `val.parquet` split (`504,037` rows, containing both `BENIGN` and known attacks).
  - Selects threshold $t$ maximizing binary F1 score against `val_df["is_attack"]`:
    - Chosen `best_thresh`: **`0.06110182785930004`** (rounded `0.061102` in `models/iforest_eval.json`).
- **Validation Performance (`models/iforest_eval.json`, `val_rows = 504,037`):**
  - `precision`: **0.5621**
  - `recall`: **0.5872**
  - `f1`: **0.5744**
  - `threshold`: **0.061102**
- **Operational Observation:** Because `best_thresh = +0.0611` is above `0.0`, it flags a substantial margin of borderline benign flows (~9.4% FPR under `BaselinePolicy`), directly motivating the `TieredSeverityPolicy` (`deep_threshold = -0.03`, `marginal_threshold = +0.061102`) and `CalibratedThresholdPolicy(target_threshold=0.0)` implemented in `src/policy.py`.

---

## 4. Runtime Compatibility Finding

- Pickle inspection (`pickletools.genops`) of `models/rf_scaler.pkl` shows the models were serialized with **scikit-learn 1.9.1** (inside the Python 3.12 `.venv`).
- On this host machine, `/usr/bin/python3` is **Python 3.14.4**, while `.venv/lib/` contains only `python3.12/site-packages`. Consequently, live Python inference, `evaluate_hybrid.py`, and `pytest` could not execute during this audit without a Python 3.12 interpreter or fresh Python 3.14 virtual environment installation.
