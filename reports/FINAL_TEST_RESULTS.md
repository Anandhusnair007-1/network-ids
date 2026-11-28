# Final Verification & Test Results

**Repository:** `/home/anandhu/projects/network-ids`  
**Python Environment:** `/home/anandhu/projects/.venv-network-ids-312` (`Python 3.12.16`)  
**Key Package Versions:** `pandas 3.1.1`, `numpy 2.5.5`, `scikit-learn 1.9.1`, `shap 0.54.1`, `streamlit 1.67.0`, `pyarrow 26.0.1`, `fastapi 0.165.0`, `uvicorn 0.54.0`, `cryptography 50.0.2`, `pytest 9.2.0`, `ruff 0.17.6`, `httpx 0.28.1`, `bandit 1.9.4`  
**Execution Policy:** Existing trained models and thresholds preserved (`models/*.pkl`, `models/iforest_threshold.json`); zero tests or source files modified.

---

## 1. Summary Matrix (All 12 Verification Gates)

| # | Check / Component | Command Executed | Expected Result | Actual Result | Status |
| :-: | :--- | :--- | :--- | :--- | :---: |
| 1 | Pytest Suite (All 8 Files) | `pytest tests/ -v --tb=short` | All tests pass without skipped artifact suites | **89 passed, 0 failed, 0 skipped** in `5.27s` (`1` Starlette `httpx` deprecation warning) | **PASS** |
| 2 | Ruff Linter | `ruff check --line-length 120 --select F,E,W --ignore E501 src/ api/ dashboard/ tests/` | Zero lint/style violations | `All checks passed!` | **PASS** |
| 3 | Python Bytecode Compilation | `python -m compileall -q src api dashboard tests` | Exit code 0 across all packages | Exit code `0`, zero syntax errors | **PASS** |
| 4 | Bandit Security Scan | `bandit -q -r src api dashboard -ll` | Zero medium/high security findings | Exit code `0` (`nosec B608` on parameterized SQL in `src/store.py:160`) | **PASS** |
| 5 | Artifact SHA-256 Integrity | `python src/security.py` | All 4 registered artifacts match `models/manifest.json` | `4/4` verified (`rf_model.pkl`, `rf_scaler.pkl`, `iforest_model.pkl`, `iforest_threshold.json`) | **PASS** |
| 6 | Dataset Loading | `pd.read_parquet(...)` on `train/val/test/withheld` + `features.json` + `label_map.json` | `78` features, `15` labels, expected row counts | `train (1512109, 81)`, `val (504037, 81)`, `test (504037, 81)`, `withheld (2179, 81)` | **PASS** |
| 7 | InputValidator | `tests/test_security_and_validation.py` + `tests/test_dashboard_integration.py` | Schema enforcement, row cap, `NaN`/`Inf` sanitization, zero-fill opt-in | `11/11` `TestInputValidation` + `TestHybridIntegrationValidation` + `3/3` upload validation tests passed | **PASS** |
| 8 | All 4 Hybrid Policies | `tests/test_alert_grouper_and_policy.py`, `test_regressions.py`, `test_dashboard_integration.py` | `tiered`, `baseline`, `balanced`, `confidence_gated` evaluate cleanly | All policy unit, parametrized registry (`4/4`), and integration tests passed | **PASS** |
| 9 | SHAP Explainability | `explain.make_explainer` + `shap_attribution` smoke & `TestShapClassAxis` | Valid feature attributions aligned to `rf.classes_` | `4/4` regression tests passed + live smoke returned `min_seg_size_forward` (`+0.0526`) | **PASS** |
| 10 | Alert Grouping & Triage KPIs | `tests/test_hybrid.py`, `test_alert_grouper_and_policy.py`, `test_regressions.py`, `test_dashboard_integration.py` | Window/gap/IP clustering + honest `summarize_groups()` KPIs | `13/13` grouping/triage tests passed | **PASS** |
| 11 | SQLite Incident Store | `tests/test_production_services.py::TestStore` | Alert-only persistence, verdict roundtrip, feedback export, SQLi inertness | `4/4` `TestStore` tests passed | **PASS** |
| 12 | FastAPI Endpoints (`TestClient`) | `tests/test_production_services.py::TestAPI` | Auth gate, JSON/CSV score, body cap `413`, rate limit `429`, metrics, audit | `7/7` `TestAPI` tests passed | **PASS** |
| 13 | Drift Monitoring | `tests/test_production_services.py::TestDrift` + live `drift.assess()` | Stable vs shifted PSI detection & live reference load | `TestDrift` passed; live smoke (`250` test rows vs `drift_reference.json`) returned `status=stable`, `median_psi=0.0184` | **PASS** |

---

## 2. Detailed Pytest Breakdown (89/89 Passed)

| Test Module | Tests | Scope Verified | Outcome |
| :--- | :---: | :--- | :---: |
| `tests/test_alert_grouper_and_policy.py` | 7 | Index-gap partitioning, `min_alerts` threshold, 60s `Timestamp` windows, empty/single row, `BaselinePolicy`, `CalibratedThresholdPolicy`, `TieredSeverityPolicy` | **7/7 PASSED** |
| `tests/test_dashboard_integration.py` | 7 | Real model loading with `BaselinePolicy`, `TieredSeverityPolicy`, `CalibratedThresholdPolicy(0.0)`, missing-feature rejection, zero-fill mode, `OversizedInputError`, real alert grouping | **7/7 PASSED** |
| `tests/test_dashboard_smoke.py` | 1 | Headless `streamlit.testing.v1.AppTest` boots `dashboard/app.py`, verifies 4 artifacts, renders `"Network intrusion detection"`, defaults selectbox to `"tiered"` | **1/1 PASSED** |
| `tests/test_hybrid.py` | 10 | `HybridDetector.predict` counts/severities (`HIGH`/`MEDIUM`/`INFO`), `predict_df` columns, `AlertGrouper` counts and `groups_to_dataframe` | **10/10 PASSED** |
| `tests/test_production_services.py` | 24 | `TestStore` (4), `TestSinks` (5), `TestDrift` (1), `TestSigning` (2), `TestSignedManifest` (1), `TestService` (3), `TestIngest` (1), `TestAPI` (7) | **24/24 PASSED** |
| `tests/test_regressions.py` | 22 | `TestShapClassAxis` (4), `TestPredictDf` (5), `TestPolicyRegistry` (5), `TestManifestRegeneration` (3), `TestAlertTriageHonesty` (3), `TestLabelDisplay` (2) | **22/22 PASSED** |
| `tests/test_security_and_validation.py` | 18 | `TestArtifactIntegrity` (7), `TestInputValidation` (10), `TestHybridIntegrationValidation` (1) | **18/18 PASSED** |
| **Total** | **89** | *Note: `tests/conftest.py` verified artifacts present so `test_dashboard_integration.py` and `test_dashboard_smoke.py` ran in full (0 skipped).* | **89/89 PASSED (`5.27s`)** |

---

## 3. Observed Warnings & Notes

- **Warning (non-failing):** `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead.` observed in `tests/test_production_services.py::TestAPI::test_probes_open_others_locked` (`fastapi/testclient.py:1` under `fastapi 0.165.0`).
- **Bandit informational notes:** `src/store.py:160` uses `# nosec B608` (parameterized `WHERE` clauses with `?` placeholders only); `src/security.py` and `src/sinks.py` have explicit `# nosec B301` / `# nosec B310` annotations after hash/URL validation. Zero medium/high warnings raised.
