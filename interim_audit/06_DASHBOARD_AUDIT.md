# 06 — Dashboard & Explainable AI Audit

**Entry Point:** `/home/anandhu/projects/network-ids/dashboard/app.py` (941 lines)  
**Supporting Modules:** `dashboard/soc_ui.py` (190 lines), `dashboard/auth.py` (59 lines), `src/explain.py` (88 lines)  
**Configuration:** `.streamlit/config.toml` (dark theme, `maxUploadSize = 50` MB, `enableXsrfProtection = true`, `gatherUsageStats = false`, `toolbarMode = "viewer"`)  
**Launch Command:** `make dashboard` -> `.venv/bin/python3 -m streamlit run dashboard/app.py` (port `8501`)

---

## 1. Authentication & Global Sidebar

- **Password Gate (`dashboard/auth.py`):** Enabled when `IDS_DASH_PASSWORD_SHA256` or `IDS_DASH_PASSWORD` is set; uses constant-time `hmac.compare_digest` over SHA-256 digests and progressive per-session sleep (`min(fails, 5)` seconds) on failed logins. Currently open if env vars are unset, displaying a sidebar warning (`Login is off...`).
- **Sidebar Controls (`dashboard/app.py` L929–939):**
  - Live **Alert policy** selector (`tiered`, `baseline`, `balanced`, `confidence_gated`) with immediate re-evaluation via `HybridDetector.with_policy()` without reloading pickles.
  - Artifact verification badge (`4 model files verified`) backed by `@st.cache_resource` `_load_base()` -> `verify_all_artifacts()` + `HybridDetector.load()`.

---

## 2. Multipage Structure (6 Pages via `st.navigation`)

| Page | Function & Lines | Functionality & Interactive Controls |
| :--- | :--- | :--- |
| **1. Overview** | `page_overview()` (`L247–360`) | Reads `reports/eval_results.json`. Plots Altair trade-off scatter (`False alarms (%)` vs `Infiltration flagged (%)` across all 4 policies), 4 KPI `ui.metric` cards (`Known attacks caught`, `False alarms`, `Alert precision`, `Novel threats flagged`), grouped Altair bar chart comparing `Classifier alone` vs `Anomaly detector alone` vs `Combined, active policy` on withheld attacks, and CIC-IDS2017 capture expander. |
| **2. Scan flows** | `page_scan()` & `render_scan_results()` (`L366–538`) | **Traffic sources:** (a) *Sample traffic* drawn from cached `test.parquet` / `withheld.parquet` pools (`Typical traffic`, `Attack-heavy`, `Novel threats only`, `100–5,000` flows or `2,179` novel cap); (b) *Upload CSV* with downloadable 78-column `flow_template.csv`, `50 MB` / `50,000`-row cap, opt-in `fill_missing` zero-imputation checkbox, and `InputValidator` enforcement.<br>**Outputs:** `ui.severity_bar()` proportional mix bar, **Flows** tab (severity multiselect, threat text search, sorted table capped at `2,000` displayed rows with `ProgressColumn` confidence and full CSV download), **Threat types** Altair horizontal bar chart, and **Ground truth check** tab (when `is_attack` or `Label` exists) showing per-attack `Flagged (%)` and `Paged (%)` recall. |
| **3. Incidents** | `page_incidents()` (`L560–654`) | Wraps `AlertGrouper` + `summarize_groups()`. Controls: severity filter, grouping mode (`Time windows of 60 seconds` if `Timestamp` present, `Threat type across the whole batch`, `Capture order`), and `Minimum flows` slider (`2–20`, default `5`). Displays KPIs (`Alerts`, `Incidents`, `Single alerts`, `Queue reduction`), selectable incident table (`on_select="rerun"`), member flow inspection, and **"Investigate this flow"** jump button (`st.switch_page`). |
| **4. Investigate flow** | `page_investigate()` (`L659–757`) | Ranks alert flows by severity and anomaly score (top 500). Shows plain-language summary, metadata (IPs, Timestamp, True label if present), custom HTML/CSS **Anomaly-score ruler** (`ui.score_ruler()`) with policy threshold ticks, and a 3-way evidence segmented control:<br>1. **Why the classifier decided** (SHAP `TreeExplainer`, selectable target class)<br>2. **How unusual the flow is** (top-15 z-score bar chart from `baseline_deviation()`)<br>3. **All feature values** (full 78-feature table with training average and z-scores). |
| **5. Alert history** | `page_history()` (`L874–911`) | Connects to SQLite `IncidentStore(DB_PATH)` written by FastAPI or `ingest_dir.py`. Filters stored alerts by severity (`HIGH/MEDIUM/LOW`) and status (`new/acknowledged/confirmed/false_positive`), displays up to 500 rows, and lets analysts record verdicts + notes (`store.set_status()`) feeding `/v1/feedback/export`. |
| **6. Detector health** | `page_health()` (`L762–862`) | Displays SHA-256 manifest verification table (`File`, `Type`, `Size`, `SHA-256`, `Status`), **Input drift** PSI assessment (`drift.assess()` vs `models/drift_reference.json` for scans `>= 200` flows), **What the classifier knows** (trained vs unseen classes), **Anomaly scores in the current scan** (Altair histogram with dashed policy threshold lines), **Threshold sensitivity** curve (`-0.15` to `+0.15` slider when ground truth exists), and **Operating limits** expander. |

---

## 3. SHAP Explainability Integration (`src/explain.py` & `dashboard/app.py`)

- **Explainer Type:** `shap.TreeExplainer(rf)` (`make_explainer()`, cached once in Streamlit via `@st.cache_resource` `get_explainer()`).
- **Local vs. Global Feature Importance:**
  - **Local (per-flow) SHAP:** Implemented and integrated. `shap_attribution()` runs `explainer.shap_values(x_scaled_row, check_additivity=False)`, maps `class_code` to its exact column index in `rf.classes_` via `class_position()` (preventing off-by-one misalignment caused by withheld classes `9`, `12`, `13`, `14`), and returns top-15 signed feature contributions (`toward class` / `away from class`) rendered as an Altair bar chart.
  - **Global SHAP summary plot:** Not computed dynamically in the dashboard (a static figure `reports/figures/fig7_top_features.png` exists in `reports/`, while runtime UI focuses on local per-flow SHAP and per-flow z-score deviation).
- **Anomaly-Only Explanations:** Because `TreeExplainer` explains why Random Forest chose its class (which is `BENIGN` on anomaly-only alerts), the dashboard defaults `MEDIUM`/`LOW` flows to `baseline_deviation()` ("How unusual the flow is") and displays a clear analyst note if SHAP is opened on an anomaly-only alert.

---

## 4. Security & UI Hardening (`dashboard/soc_ui.py`)

- **Zero External Network Calls:** No Google Fonts or CDN assets; all CSS and Altair charts render locally for isolated SOC networks.
- **XSS Protection:** Dynamic strings inserted into HTML (`ui.situation`, `ui.note`, `ui.sev_chip`, `ui.severity_bar`, `page_overview`) pass through `ui.esc()` (`html.escape(..., quote=True)`).
- **Runtime Verification Status:** Headless `tests/test_dashboard_smoke.py` (`streamlit.testing.v1.AppTest`) and `tests/test_dashboard_integration.py` exist in the repository, but could **not** be executed live during this audit because `.venv` targets Python 3.12 while the host OS currently runs Python 3.14.4 (`streamlit` / `pandas` unimportable in `.venv`). Live browser execution of the 6 pages therefore remains **pending environment fix**.
