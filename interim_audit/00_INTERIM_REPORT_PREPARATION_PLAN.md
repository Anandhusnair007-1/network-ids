# Phase 1 / Prompt 1 — Section-by-Section Interim Report Preparation Plan

**Course:** Case Study `25CSA698A` (MCA Regular, Semester 3 — Amrita Vishwa Vidyapeetham, Amrita AHEAD Online)  
**Approved Title:** Network Intrusion Detection System (IDS) *(Title #27 in `S3 MCA titles.pdf`)*  
**Student:** Anandhu S Nair | **Roll No.:** `AA.SC.P2MCA25070089`  
**Deadline:** 29th November 2026 (`S3 MCA Case Study Guidelines document (1).pdf`, p. 3)  
**Target Output (Prompt 2, not yet generated):** `/home/anandhu/projects/interim_audit/submission/` (editable `.docx` + `.pdf`, max 20 pages)

---

## 1. Template & Guideline Compliance Specifications

1. **Template Fidelity (`Interim Report Template - S3.docx`):**
   - Preserve header invocation (`Aum Amriteswaryai Namaha`), Amrita logo (`word/media/image1.png`), `Case Study 25CSA698A`, `Interim Report`, `Project Title`, `Student Name`, `Roll No.`, and final sign-off block (`Date`, `Student Name and Signature`).
   - Layout & typography from template XML: US Letter (`8.5" x 11"`), `1"` margins, **Times New Roman** (`12 pt` body/section headings, `14 pt` bold title header).
2. **Page Budget (`<= 20 pages` PDF):** Target **14–17 pages** total (leaving buffer under the 20-page hard cap):
   - Header + Abstract + Objectives: ~1.5 pages
   - Scope: ~1 page (matches template instruction)
   - Introduction: ~2.5 pages (matches template's 2–3 page instruction)
   - Background + Related Works/Existing System + Detailed Problem Statement: ~3–3.5 pages
   - Methods/Algorithms (with High-Level Design & Architecture Diagram): ~4–5 pages
   - Expected Results (with verified preliminary results, limitations & references): ~2–2.5 pages
   - AI Usage Disclosure & Sign-off: ~0.5 page
3. **Academic Integrity (`S3 MCA Case Study Guidelines document (1).pdf`):**
   - Overall similarity **<= 10%** (rewrite all prose originally; do not copy `reports/TECHNICAL_PROJECT_REPORT.md` verbatim).
   - AI usage **<= 20%** and explicitly disclosed in a short **AI Tool Usage Disclosure** note.
   - Frame withheld-category evaluation strictly as a controlled *unseen-category experiment*, never as proof of real-world zero-day detection.
   - Do **not** cite unverified runtime execution (`pytest`/live Streamlit blocked in current `.venv`) as freshly executed.

---

## 2. Section-by-Section Content & Evidence Mapping

| # | Template Section & Rule | Planned Content | Verified Project Evidence Source | Target Length |
| :-: | :--- | :--- | :--- | :---: |
| **0** | **Header Block** | Course `25CSA698A`, `Interim Report`, Title `Network Intrusion Detection System (IDS)`, Name `Anandhu S Nair`, Roll `AA.SC.P2MCA25070089`, Amrita logo. | `Interim Report Template - S3.docx`, `S3 MCA titles.pdf` (#27), `Anandhu_IDS_Proposal_Signed (1).pdf` | 0.4 pg |
| **1** | **Abstract** *(<= 250 words)* | Concise summary (~190–220 words): signature vs. closed-world ML gap; hybrid RF (200 trees) + benign-only IF (200 trees) on CIC-IDS2017 (`2,830,743` raw / `2,522,362` unique flows, 78 features); withheld-category experiment (`2,179` flows); SHAP + alert grouping + Streamlit console; verified preliminary metrics (`99.94%–99.95%` recall, `86.30%` tiered precision, `3.21%` FPR, `31/36` Infiltration capture). | `02_DATASET_ANALYSIS.md`, `03_ML_IMPLEMENTATION.md`, `05_EXPERIMENTAL_RESULTS.md`, `08_INTERIM_REPORT_DATA.md` | 0.5 pg |
| **2** | **Objectives** *(Bullets, >= 2)* | 5–6 clear bullets separating implemented core objectives (data audit/dedup/split, RF+IF dual engine + policies, withheld-category benchmark, SHAP + alert grouping + SHA-256 console) from remaining final-phase objectives (runtime test restoration, reproducible timing/confusion-matrix benchmark, final demo/report). | `Anandhu_IDS_Proposal_Signed (1).pdf`, `07_IMPLEMENTATION_STATUS.md`, `08_INTERIM_REPORT_DATA.md` | 0.6 pg |
| **3** | **Scope** *(~1 page)* | Exact boundaries: CIC-IDS2017 bidirectional flow summaries (78 features, not inline packet DPI); 11 supervised classes vs. 4 withheld classes; algorithms (`StandardScaler`, RF, IF, policies, SHAP, `AlertGrouper`, Streamlit); explicit limitations (HTTP payload blindness 6%–19%, 2017 lab traffic, no live traffic validation, optional API/SIEM extensions kept distinct). | `README.md`, `02_DATASET_ANALYSIS.md`, `08_INTERIM_REPORT_DATA.md` | 1.0 pg |
| **4** | **Introduction** *(2–3 pages)* | 4 subsections: (4.1) Network intrusion detection overview & operational challenges; (4.2) Literature synthesis & closed-world vs. anomaly-fatigue dilemma; (4.3) Specific aims & research questions (RQ1–RQ4); (4.4) Report & system structure overview. | `TECHNICAL_PROJECT_REPORT.md` (§3–4 rewritten originally), `08_INTERIM_REPORT_DATA.md` | 2.5 pg |
| **5** | **Background** | Technical foundations of NIDS, signature detection (Snort/Suricata), supervised ML (Random Forest), semi-supervised anomaly detection (Isolation Forest path-length isolation), and XAI (Shapley / `TreeExplainer`), plus proposed pipeline layout. | `04_HYBRID_ARCHITECTURE.md`, `08_INTERIM_REPORT_DATA.md` | 1.2 pg |
| **6** | **Related Works / Existing System** | Structured review of the 10 verified scholarly papers (Sharafaldin 2018; Breiman 2001; Liu 2008; Lundberg & Lee 2017; Lundberg 2020; Ahmad 2021; Sarhan 2021; Engelen 2021; Rosay 2022; Lanvin 2023) + comparison table (Signature vs. Supervised ML vs. Anomaly-Only vs. Proposed Hybrid) concluding with the identified research gap. | `TECHNICAL_PROJECT_REPORT.md` (§5, §6, §14), `08_INTERIM_REPORT_DATA.md` | 1.8 pg |
| **7** | **Detailed Problem Statement** | Explicit **Current State** -> **Desired Future State** -> **Gaps** mapping: (1) Zero-day/unseen-class blindness of rules & closed-world RF; (2) 9.42% FPR alert flood of raw IF; (3) Opaque black-box alerts; (4) CIC-IDS2017 duplicate/leakage pitfalls. | `Interim Report Template - S3.docx`, `05_EXPERIMENTAL_RESULTS.md`, `08_INTERIM_REPORT_DATA.md` | 0.8 pg |
| **8** | **Methods / Algorithms** | High-Level Design & Module Breakdown: (8.1) System Architecture Diagram (fresh diagram matching actual 6-page + 4-policy pipeline); (8.2) Dataset Cleaning & Leakage-Resistant Splitting (`preprocess.py`, raw vs. deduplicated counts table); (8.3) Feature Schema & `InputValidator`; (8.4) Random Forest (`train_rf.py`); (8.5) Isolation Forest & Val Calibration (`train_iforest.py`); (8.6) Hybrid Decision Policies (`hybrid.py`, `policy.py` decision table); (8.7) SHAP & Z-Score Explainability (`explain.py`); (8.8) Alert Grouping (`alert_grouper.py`); (8.9) Streamlit Console & Artifact Security (`security.py`, `dashboard/app.py`); (8.10) Evaluation Metrics & Formulas. | `01_PROJECT_INVENTORY.md`, `02_DATASET_ANALYSIS.md`, `03_ML_IMPLEMENTATION.md`, `04_HYBRID_ARCHITECTURE.md`, `06_DASHBOARD_AUDIT.md` | 4.5 pg |
| **9** | **Expected Results** | Verified interim findings & remaining targets: (9.1) Known-attack baseline vs. 4 hybrid policies table (`504,037` test rows); (9.2) Withheld-category table (`2,179` rows, `31/36` Infiltration, `6%–19%` Web attacks with WAF caveat); (9.3) Expected explainability, triage & runtime verification outcomes (explicitly noting confusion matrices, reproducible latency benchmark, and `.venv` test execution are scheduled for the final phase); (9.4) Limitations & Future Work. | `05_EXPERIMENTAL_RESULTS.md`, `07_IMPLEMENTATION_STATUS.md`, `08_INTERIM_REPORT_DATA.md`, `09_GAPS_AND_NEXT_STEPS.md` | 2.2 pg |
| **10** | **References, AI Disclosure & Sign-Off** | APA references (10 verified citations only), concise AI Tool Usage Disclosure (`<= 20%` supporting use per guidelines), and template `Date` + `Student Name and Signature` block. | `S3 MCA Case Study Guidelines document (1).pdf`, `Interim Report Template - S3.docx`, `TECHNICAL_PROJECT_REPORT.md` (§14) | 0.8 pg |

---

## 3. Missing Information & Risks Identified Before Prompt 2

1. **Outdated `Oct 20` Figures (`reports/figures/`):** Existing `fig1_system_architecture.png`, `fig4_rf_vs_hybrid_metrics.png`, and `fig8_alert_compression.png` predate Phase D changes (`TieredSeverityPolicy`, 6-page UI, updated `summarize_groups()`). **Plan:** Generate clean, accurate architecture & policy-comparison figures directly from `reports/eval_results.json` (using Python/matplotlib or system python/Pillow if needed, or inspect existing PNGs first before embedding) rather than embedding stale numbers (`99.56%` compression or 5-page UI).
2. **Unpersisted Confusion Matrices & Conflicting Latency Figures:** `reports/eval_results.json` lacks raw confusion matrices, and docs disagree on latency (`12.16 us` vs `15.79 us` vs `47k flows/s`). **Plan:** In the Interim Report, omit unverified latency claims and report confusion matrices / standardized latency benchmarking as **scheduled final-phase work** (Phase 4 / Prompt 5), while reporting only verified metrics from `eval_results.json`, `rf_eval.json`, and `iforest_eval.json`.
3. **Runtime Test Execution Blocked in `.venv`:** Do not claim `89/89 pytest passed` as observed in this audit; accurately report static/integrity verification (`security.py` 4/4 verified, `ruff` clean) and list full test-suite re-execution in the restored environment (Phase 2–3) as pending verification.
4. **DOCX/PDF Generation Tooling Check Needed Before Prompt 2:** Check whether `python-docx` and LibreOffice (`soffice`) exist on `/usr/bin/python3` / host OS before running Prompt 2.
5. **Submission Date & Final Date:** Interim Report due `29th November 2026`. Report date field should use `26 November 2026` (or `29 November 2026` if desired—user can confirm).
