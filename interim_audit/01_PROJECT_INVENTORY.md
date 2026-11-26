# 01 — Project Inventory

**Repository Path:** `/home/anandhu/projects/network-ids`  
**Git Branch / HEAD:** `phase-d-release-hardening` (`e313f18`), branched after `e408ea0` (`main`), with uncommitted working-tree edits and untracked production-layer files.  
**Audit Method:** Complete read-only inspection of source files, configurations, artifacts, git log, and non-mutating checks (`src/security.py`, `ruff`).

---

## 1. Complete Directory Structure & Purpose

```text
/home/anandhu/projects/network-ids/
├── api/                         # FastAPI scoring REST service (untracked production extension)
│   ├── __init__.py
│   └── main.py                  # Auth, streaming body limit, rate limit, /v1/* endpoints, /metrics
├── Claude outputs/              # Staged GitHub Actions CI workflow (not yet in .github/workflows/)
│   └── ci.yml
├── dashboard/                   # Interactive Streamlit SOC console
│   ├── app.py                   # 6-page multipage console (Overview, Scan, Incidents, Investigate, History, Health)
│   ├── auth.py                  # Optional SHA-256 password gate (untracked)
│   └── soc_ui.py                # Dark-theme CSS, Altair styling, severity chips, score ruler (untracked)
├── data/
│   ├── processed/               # Cleaned, split Parquet datasets + schema metadata (352 MB total)
│   │   ├── features.json        # 78 canonical feature names
│   │   ├── label_map.json       # Integer code -> class label (0..14)
│   │   ├── train.parquet        # 212 MB (60% known categories)
│   │   ├── val.parquet          # 71 MB (20% known categories)
│   │   ├── test.parquet         # 71 MB (20% known categories)
│   │   └── withheld.parquet     # 269 KB (4 unseen attack categories)
│   └── raw/MachineLearningCVE/  # 8 CIC-IDS2017 CSV files (844 MB total, 2,830,743 data rows)
├── docs/                        # Operational documentation (untracked)
│   ├── DEPLOYMENT.md
│   ├── RUNBOOK.md
│   └── SECURITY.md
├── models/                      # Serialized ML models, thresholds, evals, integrity manifest (80 MB)
│   ├── drift_reference.json     # Quantile bins for PSI drift monitoring (12 KB)
│   ├── iforest_eval.json        # Validation metrics for Isolation Forest
│   ├── iforest_model.pkl        # Pickled IsolationForest (1.4 MB)
│   ├── iforest_threshold.json   # Calibrated threshold (0.06110182785930004)
│   ├── manifest.json            # SHA-256 registry for 4 core artifacts
│   ├── rf_eval.json             # Validation metrics for Random Forest
│   ├── rf_model.pkl             # Pickled RandomForestClassifier (79 MB)
│   └── rf_scaler.pkl            # Pickled StandardScaler (2.3 KB)
├── reports/                     # Benchmark outputs, charts, and generated academic report
│   ├── dataset_audit.txt        # Raw CSV audit output
│   ├── eval_results.json        # Test, withheld, and 4-policy comparison metrics
│   ├── figures/                 # 7 PNG figures (fig1, fig2, fig4, fig5, fig6, fig7, fig8)
│   ├── generate_report_docx.py  # Script generating DOCX report
│   ├── Network_IDS_Project_Report_Anandhu_S_Nair.docx
│   ├── Network_IDS_Project_Report_Anandhu_S_Nair.pdf
│   └── TECHNICAL_PROJECT_REPORT.md
├── src/                         # Core ML pipeline, hybrid engine, security, and production services
│   ├── __init__.py
│   ├── alert_grouper.py         # Temporal / sequential alert consolidation
│   ├── audit_dataset.py         # Non-destructive raw CSV auditor
│   ├── build_drift_reference.py # Builds models/drift_reference.json from val.parquet
│   ├── config.py                # Centralized paths, IDS_* env overrides, label normalizer
│   ├── drift.py                 # Population Stability Index (PSI) drift computation
│   ├── evaluate_hybrid.py       # Offline evaluation (test split, withheld split, policy matrix)
│   ├── explain.py               # SHAP TreeExplainer + scaler z-score baseline deviation
│   ├── hybrid.py                # HybridDetector orchestrating RF + IF + policy
│   ├── ingest_dir.py            # Chunked CSV inbox directory watcher
│   ├── policy.py                # 4 arbitration policies + build_policy() registry
│   ├── preprocess.py            # Cleaning, deduplication, withheld isolation, stratified split
│   ├── security.py              # SHA-256 verification before pickle.load + manifest writer
│   ├── service.py               # Unified ScoringService (validate -> score -> store -> sinks -> drift)
│   ├── signing.py               # Ed25519 manifest signing and verification
│   ├── sinks.py                 # UDP Syslog CEF and HMAC-signed Webhook SIEM exporters
│   ├── store.py                 # SQLite WAL IncidentStore + feedback export
│   ├── train_iforest.py         # Benign-only Isolation Forest training + val threshold sweep
│   ├── train_rf.py              # StandardScaler + balanced Random Forest training
│   └── validator.py             # InputValidator (78-feature schema, row cap, NaN/Inf sanitization)
├── tests/                       # 8 pytest test suites (unit, security, regression, integration, API)
├── .streamlit/config.toml       # Dark theme, 50 MB upload cap, telemetry disabled
├── .venv/                       # Python 3.12 virtualenv (763 MB; broken on host Python 3.14.4)
├── Anandhu_IDS_Proposal_Signed (1).pdf
├── Dockerfile                   # Non-root container image (API default CMD)
├── docker-compose.yml           # api, dashboard, and ingest services
├── Makefile                     # Task automation (install, audit, preprocess, train-*, evaluate, check, dashboard)
├── README.md                    # System documentation
├── requirements.txt             # Runtime dependencies (11 packages)
└── requirements-dev.txt         # Dev/test/lint/security dependencies
```

---

## 2. Main Application Entry Points

| Entry Point | Command | Purpose |
| :--- | :--- | :--- |
| Streamlit SOC Console | `make dashboard` (`streamlit run dashboard/app.py`) | Interactive 6-page analyst console (`http://localhost:8501`) |
| FastAPI Scoring Service | `uvicorn api.main:app --host 0.0.0.0 --port 8000` | Authenticated REST API for JSON/CSV scoring, alert triage, Prometheus metrics |
| Folder Ingestor | `python src/ingest_dir.py [--once]` | Polls `var/ingest/inbox/` for CSVs, streams chunks through `ScoringService` |
| Training & Eval Pipeline | `make all` (`preprocess` -> `train-rf` -> `train-iforest` -> `evaluate`) | Rebuilds processed splits, models, and `reports/eval_results.json` |
| Artifact Verification | `make verify-artifacts` (`python src/security.py`) | Verifies SHA-256 hashes of all 4 files in `models/manifest.json` |

---

## 3. Core Module Responsibilities (`src/`)

- **`config.py`**: Resolves paths (`PROJECT_ROOT`, `DATA_DIR`, `RAW_DATA_DIR`, `MODELS_DIR`, `REPORTS_DIR`, `VAR_DIR`, `DB_PATH`, `AUDIT_LOG_PATH`), operational ceilings (`MAX_UPLOAD_ROWS=50000`, `MAX_UPLOAD_BYTES=50MB`), policy/auth/SIEM env vars, and `pretty_label()` to repair `cp1252` en-dash mojibake (`\ufffd`, `\x96`).
- **`validator.py`**: `InputValidator` enforces presence of all 78 features from `features.json`, enforces `max_rows`, coerces non-numeric columns with `pd.to_numeric(..., errors="coerce")`, replaces `±Inf` and `NaN` with `0.0`, and casts to `np.float32`.
- **`security.py` & `signing.py`**: `safe_load_pickle()` checks SHA-256 digests (`hmac.compare_digest`) against `models/manifest.json` before invoking `pickle.load`. If `IDS_MANIFEST_PUBKEY` is configured, `load_manifest()` enforces an Ed25519 signature (`manifest.json.sig`) first.
- **`hybrid.py` & `policy.py`**: `HybridDetector` loads `rf_model.pkl`, `iforest_model.pkl`, `rf_scaler.pkl`, `label_map.json`, and `iforest_threshold.json`. `signals()` computes `rf.predict_proba()` once (deriving class codes via `rf.classes_[argmax]`) and `iforest.decision_function()`, then `apply_policy()` delegates to one of 4 vectorized `HybridDecisionPolicy` implementations.
- **`explain.py`**: `make_explainer()` builds `shap.TreeExplainer(rf)`. `shap_attribution()` maps `class_code` to `rf.classes_` position via `class_position()` and extracts top-$k$ signed contributions. `baseline_deviation()` computes per-feature z-scores against `scaler.mean_` and `scaler.scale_`.
- **`alert_grouper.py`**: `AlertGrouper` consolidates non-`INFO` flows by `(final_label, severity)` plus detected IP columns (`SRC_IP_ALIASES`, `DST_IP_ALIASES`), using 60s tumbling windows when `Timestamp` exists or bounded sequential index gaps (`max_index_gap=50`, `max_group_size=1000`). `summarize_groups()` computes honest queue reduction keeping ungrouped alerts (`< min_alerts`) in the analyst queue.
- **`service.py`, `store.py`, `sinks.py`, `drift.py`, `ingest_dir.py`**: Production service layer built on top of `HybridDetector`. Persists alerts in SQLite WAL (`var/ids.sqlite3`), exports `HIGH`/`MEDIUM` alerts via UDP CEF syslog or HMAC-SHA256 webhooks, tracks feature/score PSI drift against `models/drift_reference.json`, and supports analyst feedback export (`/v1/feedback/export`).

---

## 4. Execution Workflow

1. **Offline Training**: `audit_dataset.py` -> `preprocess.py` -> `train_rf.py` -> `train_iforest.py` -> `src/security.py --update` -> `evaluate_hybrid.py` -> `build_drift_reference.py`.
2. **Runtime Verification**: At startup, `HybridDetector.load()` verifies SHA-256 (and optional Ed25519 signature) of model files prior to unpickling.
3. **Online / Batch Scoring**: Input flows pass through `InputValidator` -> `StandardScaler` -> `HybridDetector.signals()` -> active `HybridDecisionPolicy` -> `AlertGrouper` / `IncidentStore` / `SinkManager` / `drift.assess()` -> Streamlit UI or JSON API response.
