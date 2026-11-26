# 10 — Evidence Index

Complete traceability index of files inspected, key symbols, and live read-only command outputs observed during this audit.

---

## 1. Academic & Requirement Documents Inspected

| File | Key Evidence Extracted |
| :--- | :--- |
| `/home/anandhu/Downloads/Anandhu_IDS_Proposal_Signed (1).pdf` | Course `21CSA391A`, Student `Anandhu S Nair`, Roll `AA.SC.P2MCA25070089`, Title `Network Intrusion Detection System (IDS)`, Hybrid RF + IF on CIC-IDS2017, withheld attacks, SHAP, Streamlit, baseline comparison metrics |
| `/home/anandhu/Downloads/S3 MCA titles.pdf` | 75 approved MCA S3 titles; `#27 Network Intrusion Detection System (IDS)` matches proposal |
| `/home/anandhu/Downloads/S3 MCA Case Study Guidelines document (1).pdf` | Course `25CSA698A`, 3 credits; Interim Report due `29th November 2026` (20%, max 20-page PDF); Final Report (`24th January 2026` in doc, 20%, max 20-page PDF); Code review & Demo (20%); Presentation (20%); Viva (10%); similarity `<= 10%`; AI usage `<= 20%` with disclosure |
| `/home/anandhu/Downloads/Interim Report Template - S3.docx` | Course `25CSA698A`; exact required sections: `Abstract (<=250 words)`, `Objectives`, `Scope (1 page)`, `Introduction (2–3 pages)`, `Background`, `Related Works/Existing System`, `Detailed Problem Statement`, `Methods/Algorithms`, `Expected Results` |

---

## 2. Source Code & Configuration References (`/home/anandhu/projects/network-ids`)

| Component | File Path | Key Symbols / Line References |
| :--- | :--- | :--- |
| Configuration | `src/config.py` (`L1–96`) | `MAX_UPLOAD_ROWS=50000`, `MAX_UPLOAD_BYTES=50MB`, `DEFAULT_POLICY="tiered"`, `pretty_label()` (`L56–61`), `IDS_*` env vars |
| Dataset Audit | `src/audit_dataset.py` (`L1–83`) | Chunked CSV reader (`cp1252`), label/null/inf reporting |
| Preprocessing | `src/preprocess.py` (`L1–244`) | `WITHHELD_PREFIXES` (`L61–64`), `DROP_COLS` (`L71–77`), `_clean()` (`L106–128`), `_encode_labels()` (`L131–148`), `_split_withheld()` (`L151–169`), `_stratified_split()` (`L172–188`) |
| RF Training | `src/train_rf.py` (`L1–156`) | `StandardScaler()` (`L85`), `RandomForestClassifier(n_estimators=200, max_depth=None, class_weight="balanced", random_state=42)` (`L91–97`) |
| IF Training | `src/train_iforest.py` (`L1–149`) | `benign_mask = train_df["Label"] == "BENIGN"` (`L72`), `IsolationForest(n_estimators=200, contamination=0.05, random_state=42)` (`L82–87`), 40-percentile sweep (`L99–105`) |
| Hybrid Engine | `src/hybrid.py` (`L1–293`) | `HybridResult` (`L61–68`), `HybridDetector.load()` (`L120–158`), `with_policy()` (`L161–170`), `signals()` (`L173–193`), `apply_policy()` (`L196–206`), `predict()` (`L221–246`), `predict_df()` (`L249–293`) |
| Policies | `src/policy.py` (`L1–247`) | `HybridDecisionPolicy`, `BaselinePolicy`, `CalibratedThresholdPolicy`, `TieredSeverityPolicy` (`deep=-0.03`, `marginal=0.061102`), `ConfidenceGatedPolicy`, `POLICY_INFO`, `build_policy()` |
| Validation | `src/validator.py` (`L1–169`) | `InputValidator.validate_df()` (`L73–142`), `validate_array()` (`L144–169`), `MissingFeatureError`, `OversizedInputError` |
| Artifact Security | `src/security.py` (`L1–229`) | `compute_file_sha256()`, `load_manifest()` (checks `MANIFEST_PUBKEY`), `verify_artifact_integrity()` (`hmac.compare_digest`), `safe_load_pickle()`, `write_manifest()` |
| Manifest Signing | `src/signing.py` (`L1–97`) | `generate_keypair()`, `sign_manifest()`, `verify_manifest_signature()` (Ed25519) |
| Explainability | `src/explain.py` (`L1–88`) | `class_position()`, `_slice_for_class()`, `make_explainer()` (`shap.TreeExplainer`), `shap_attribution()`, `baseline_deviation()` |
| Alert Grouping | `src/alert_grouper.py` (`L1–305`) | `AlertGrouper.group()`, `_sequential_index_group()`, `_window_group()`, `groups_to_dataframe()`, `summarize_groups()` (`L285–305`) |
| Evaluation | `src/evaluate_hybrid.py` (`L1–252`) | `compare_policies()` (`L80–126`), `main()` (`L129–249`) |
| Production Service | `src/service.py` (`L1–163`) | `ScoringService.from_config()`, `ScoringService.score()` (`L92–143`) |
| Incident Store | `src/store.py` (`L1–210`) | `IncidentStore` (SQLite WAL), `save_batch()`, `list_alerts()`, `set_status()`, `export_feedback()` |
| SIEM Sinks | `src/sinks.py` (`L1–131`) | `to_cef()`, `SyslogCEFSink`, `WebhookSink` (HMAC-SHA256), `SinkManager` |
| Drift Monitor | `src/drift.py` (`L1–113`), `src/build_drift_reference.py` (`L1–35`) | `build_reference()`, `assess()` (`MIN_ROWS=200`, `PSI_MODERATE=0.10`, `PSI_SIGNIFICANT=0.25`) |
| Folder Ingestor | `src/ingest_dir.py` (`L1–97`) | `process_file()`, `run()` (skips symlinks, `SETTLE_SECONDS=2.0`, chunked `MAX_UPLOAD_ROWS`) |
| FastAPI Service | `api/main.py` (`L1–371`) | `BodyLimitMiddleware`, `RateLimiter`, `create_app()`, `/healthz`, `/readyz`, `/metrics`, `/v1/policies`, `/v1/score`, `/v1/score/csv`, `/v1/alerts*`, `/v1/stats`, `/v1/feedback/export` |
| Streamlit Console | `dashboard/app.py` (`L1–941`), `soc_ui.py` (`L1–190`), `auth.py` (`L1–59`) | `page_overview`, `page_scan`, `page_incidents`, `page_investigate`, `page_history`, `page_health`, `score_ruler()`, `require_login()` |
| Test Suites | `tests/*.py` (8 files) | `conftest.py`, `test_hybrid.py`, `test_security_and_validation.py`, `test_alert_grouper_and_policy.py`, `test_regressions.py`, `test_production_services.py`, `test_dashboard_integration.py`, `test_dashboard_smoke.py` |
| Ops & Docs | `Makefile`, `Dockerfile`, `docker-compose.yml`, `.streamlit/config.toml`, `Claude outputs/ci.yml`, `docs/*.md`, `README.md` | Build, container hardening (`ids` user, `read_only: true`, `cap_drop: [ALL]`), CI definition |

---

## 3. Data, Model & Report Artifacts Verified

- **Raw CSVs:** `data/raw/MachineLearningCVE/*.csv` (8 files, 844 MB, `2,830,751` total lines = `2,830,743` data rows).
- **Processed Splits:** `data/processed/{train.parquet (212M), val.parquet (71M), test.parquet (71M), withheld.parquet (269K), features.json (78 features), label_map.json (15 labels)}`.
- **Models & Evals:** `models/{rf_model.pkl (79M), iforest_model.pkl (1.4M), rf_scaler.pkl (2.3K, sklearn 1.9.1), iforest_threshold.json (0.06110182785930004), manifest.json, rf_eval.json, iforest_eval.json, drift_reference.json (12K)}`.
- **Reports & Figures:** `reports/eval_results.json`, `reports/dataset_audit.txt`, `reports/TECHNICAL_PROJECT_REPORT.md`, `reports/generate_report_docx.py`, `reports/Network_IDS_Project_Report_Anandhu_S_Nair.{docx,pdf}`, `reports/figures/fig{1,2,4,5,6,7,8}_*.png`.

---

## 4. Read-Only Checks Executed During Audit

| Check Command | Outcome | Observed Evidence |
| :--- | :--- | :--- |
| `.venv/bin/python3 src/security.py` | **PASSED** | `All 4 artifacts passed cryptographic integrity verification.` (`rf_model.pkl`, `rf_scaler.pkl`, `iforest_model.pkl`, `iforest_threshold.json`) |
| `.venv/bin/ruff check --line-length 120 --select F,E,W --ignore E501 src api dashboard tests` | **PASSED** | `All checks passed!` |
| `wc -l data/raw/MachineLearningCVE/*.csv` & `head -n 1` | **PASSED** | `2,830,751` total lines across 8 CSVs; 79 columns per CSV (78 features + `Label`, duplicate `Fwd Header Length`) |
| `pickletools.genops(models/rf_scaler.pkl)` | **PASSED** | Confirmed `StandardScaler` serialized under `_sklearn_version 1.9.1` |
| `.venv/bin/python3 -m pytest ...` / `import pandas` | **FAILED (Env)** | Host `/usr/bin/python3` is `3.14.4` while `.venv/lib/` only has `python3.12/site-packages` (`ModuleNotFoundError: No module named 'pandas'`, `No module named pip`) |
| `git status --short` & `git log --stat -n 5` | **PASSED** | Branch `phase-d-release-hardening` (`e313f18`), 16 modified tracked files, untracked `api/`, `docs/`, `Dockerfile`, `docker-compose.yml`, etc. |
