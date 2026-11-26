# 08 — Interim Report Data Mapping (Amrita MCA S3 — `25CSA698A`)

**Header Fields Required by `Interim Report Template - S3.docx`:**
- **Course:** Case Study `25CSA698A`
- **Document:** Interim Report (Max 20-page PDF; due **29th November 2026**)
- **Project Title:** Network Intrusion Detection System (IDS) *(matches Title #27 in `S3 MCA titles.pdf`)*
- **Student Name:** Anandhu S Nair
- **Roll No.:** AA.SC.P2MCA25070089

*(Note: Every metric and detail below is verified from repository artifacts. Do not copy `TECHNICAL_PROJECT_REPORT.md` verbatim into final submissions without checking the <= 10% similarity and <= 20% AI-usage rules in `S3 MCA Case Study Guidelines document (1).pdf`.)*

---

## Abstract *(Template Limit: Not more than 250 words)*

**Draft Material / Verified Data Points (~195 words):**
Signature-based Network Intrusion Detection Systems (NIDS) accurately detect known threats but fail against unmodeled or novel attacks. Conversely, purely supervised machine learning classifiers operate under a closed-world assumption and frequently misclassify unseen attack families as benign traffic. This case study designs, implements, and evaluates a hybrid ML-based Network Intrusion Detection System combining a supervised Random Forest classifier (200 trees, balanced class weights) with a semi-supervised Isolation Forest anomaly detector (200 trees) on the CIC-IDS2017 benchmark dataset (2,830,743 raw flows; 2,522,362 deduplicated flows across 78 statistical features). To evaluate novel-threat visibility without data leakage, four attack categories—Infiltration and three Web Attack variants (`N = 2,179` flows)—are withheld completely from supervised training, while Isolation Forest is trained exclusively on benign flows (`1,257,890` records) with its threshold (`0.061102`) calibrated on a separate validation split (`504,037` flows). The hybrid system is compared against a Random Forest-only baseline across precision, recall, F1-score, false positive rate, alert volume, and inference latency, while integrating SHAP `TreeExplainer`, z-score baseline deviation, and temporal alert grouping inside a Streamlit console. Preliminary evaluation on `504,037` test flows confirms high known-attack recall (99.94%–99.95%) and 86.11% Infiltration anomaly capture alongside a precision–false-alarm trade-off managed through tiered severity policies.

---

## Objectives *(Template: Bullet points, at least 2 objectives)*

**Implemented Objectives (Verified in Repository):**
- **Objective 1 — Leakage-Resistant Data Engineering:** Audit, clean, deduplicate (`308,381` duplicates removed), and partition the CIC-IDS2017 corpus into stratified known-category splits (`60/20/20`) and a strictly isolated withheld-attack split (`2,179` flows), dropping socket identifiers.
- **Objective 2 — Dual-Engine Hybrid Detection:** Build and compare a supervised 200-tree Random Forest classifier against a benign-only Isolation Forest anomaly detector combined via configurable arbitration policies (`Baseline`, `Tiered`, `Balanced`, `Confidence-Gated`).
- **Objective 3 — Unseen-Category & Baseline Benchmarking:** Measure detection rates on withheld attacks (`Infiltration` and `Web Attacks`) and quantify false-positive overhead relative to a classifier-only baseline.
- **Objective 4 — Explainable SOC Triage & Dashboard:** Integrate SHAP `TreeExplainer` local attributions, baseline z-score deviations, and sliding-window/sequential alert grouping into an interactive Streamlit console backed by SHA-256 artifact verification.

**Pending / Remaining Verification Objectives (for Final Phase):**
- **Objective 5 — Environment & Reproducibility Verification:** Restore a compatible Python runtime to execute the full `pytest` suite, record confusion matrices and reproducible inference timing benchmarks, and verify live Streamlit rendering.
- **Objective 6 — Final Report & Demo Preparation:** Complete end-semester evaluation documentation, prepare the live demonstration, and disclose AI tool usage within the 20% guideline limit.

---

## Scope *(Template: Explain scope in ~1 page)*

- **Dataset Scope:** Offline bidirectional network flow summary records from the public CIC-IDS2017 `MachineLearningCVE` dataset (8 CSV files, 78 numeric flow timing, packet-size, flag, and subflow statistics).
- **Attack Detection Scope:**
  - *Known supervised classes (11 total):* `BENIGN`, `Bot`, `DDoS`, `DoS GoldenEye`, `DoS Hulk`, `DoS Slowhttptest`, `DoS slowloris`, `FTP-Patator`, `Heartbleed`, `PortScan`, `SSH-Patator`.
  - *Withheld evaluation classes (4 total):* `Infiltration`, `Web Attack – Brute Force`, `Web Attack – XSS`, `Web Attack – Sql Injection` (used strictly as an unseen-category benchmark, not proof of real-world zero-day coverage).
- **Algorithmic & Architectural Scope:** `StandardScaler`, `RandomForestClassifier`, `IsolationForest`, rule-based hybrid severity arbitration (`HIGH`/`MEDIUM`/`LOW`/`INFO`), `AlertGrouper`, SHAP `TreeExplainer`, and Streamlit visualization (plus optional FastAPI/SQLite/SIEM/PSI-drift production extensions).
- **Out-of-Scope / Explicit Boundaries:**
  - Not a raw packet sniffer (`pcap`/inline DPI) or encrypted payload inspector; requires upstream flow extractors (e.g., `CICFlowMeter`, `Zeek`) for live deployment.
  - Application-layer web payloads (`XSS`, `SQLi`, `Brute Force`) resemble normal HTTP flows in 78 transport features (only 6%–19% detected) and require a complementary WAF.
  - Thresholds are tuned solely on 2017 CIC-IDS2017 lab traffic and have not been validated on live enterprise traffic.

---

## Introduction *(Template: 2–3 pages: general intro, literature review, aims/objectives, project structure)*, Background, Related Works & Detailed Problem Statement

### 3.1 Background
- **Network Intrusion Detection Systems (NIDS):** Monitor network telemetry to detect unauthorized access, denial-of-service floods, reconnaissance scans, and lateral movement.
- **Signature-Based Detection:** Tools such as Snort and Suricata match deterministic rules against known byte patterns or protocol anomalies with near-zero false positives, but remain blind to novel or mutated attacks lacking signatures.
- **Supervised Machine Learning Detection:** Algorithms like Random Forest learn non-linear decision boundaries across flow statistics, achieving >99% accuracy on benchmark splits, yet fail silently under closed-world constraints when unseen attack classes appear.
- **Unsupervised Anomaly Detection:** Algorithms such as Isolation Forest model normal (`BENIGN`) behavioral envelopes and isolate statistical outliers without attack labels, enabling detection of novel deviations at the cost of higher false-positive rates.

### 3.2 Related Works / Existing System *(Verified Scholarly Citations Only)*
All citations below are verified in `reports/TECHNICAL_PROJECT_REPORT.md` (§14) and `README.md` (§10):
1. **Sharafaldin, Lashkari, & Ghorbani (2018)** *(ICISSP)* — Introduced CIC-IDS2017 covering realistic benign backgrounds and modern attack scenarios across 5 days.
2. **Breiman (2001)** *(Machine Learning)* — Established Random Forests using bagging and random feature subspaces.
3. **Liu, Ting, & Zhou (2008)** *(IEEE ICDM)* — Introduced Isolation Forest, isolating anomalies via shorter expected path lengths in randomized trees.
4. **Lundberg & Lee (2017)** *(NeurIPS)* & **Lundberg et al. (2020)** *(Nature Machine Intelligence)* — Formulated SHAP and polynomial-time `TreeExplainer` for exact tree-ensemble feature attributions.
5. **Ahmad et al. (2021)** *(Trans. Emerging Telecom. Tech.)* & **Sarhan et al. (2021)** *(IEEE Access)* — Surveyed and benchmarked ML/DL NIDS paradigms across tabular flow datasets, showing strong efficiency of tree ensembles.
6. **Engelen, Rimmer, & Joosen (2021)** *(ACM AISEC)*, **Rosay, Carlier, & Leroux (2022)** *(IEEE LCN)*, & **Lanvin, Sommer, & Cavalli (2023)** *(IEEE TNSM)* — Identified CIC-IDS2017 pipeline pitfalls (duplicates, infinite values, labeling artifacts) motivating strict cleaning and deduplication before splitting.

**Gap Identified in Existing Systems:** Most academic ML-NIDS works report closed-world accuracy on leaked or un-deduplicated splits without testing withheld attack families, quantifying false-alarm inflation from anomaly detection, or providing analyst-facing triage and explanations.

### 3.3 Detailed Problem Statement
- **Current State:** Signature engines miss unknown threats; purely supervised classifiers misclassify novel attacks (e.g., `Infiltration` predicted 100% as `BENIGN` by RF alone); raw anomaly detectors flood analysts with false alarms (~9.42% FPR in `BaselinePolicy`), and black-box scores lack justification.
- **Desired Future State:** A reproducible hybrid IDS combining high-precision known-attack classification, benign-trained anomaly detection for novel behaviors, tiered severity triage + alert grouping to control workload, and per-flow XAI evidence.
- **Gap Bridged:** Controlled withheld-category evaluation + policy-driven severity tiering (`TieredSeverityPolicy` cutting actionable FPR from `9.42%` to `3.21%`) + SHAP / z-score investigation UI.

---

## Methods / Algorithms *(Mapped to Implemented Codebase)*
1. **Preprocessing (`src/preprocess.py`):** Strip whitespace, decode `cp1252`, replace `±Inf`/`NaN` with `0`, drop `308,381` exact duplicates, hold out `2,179` unseen-category flows, and run `60/20/20` stratified split (`random_state=42`).
2. **Feature Engineering & Scaling:** Retain 78 CIC-IDS2017 statistical features (`features.json`), drop socket identifiers (`DROP_COLS`), standardize via `StandardScaler` fit on `train.parquet`, and enforce runtime schema/DoS caps via `InputValidator` (`<= 50,000` rows, `<= 50 MB`, `float32`).
3. **Random Forest (`src/train_rf.py`):** `RandomForestClassifier(n_estimators=200, max_depth=None, class_weight="balanced", random_state=42)` on 11 known classes; single-pass `predict_proba()` inference in `HybridDetector.signals()`.
4. **Isolation Forest (`src/train_iforest.py`):** `IsolationForest(n_estimators=200, contamination=0.05, random_state=42)` fit strictly on `1,257,890` `BENIGN` training rows; threshold `0.061102` calibrated via validation F1 sweep (`val.parquet`).
5. **Hybrid Decision Arbitration (`src/hybrid.py`, `src/policy.py`):** Vectorized arbitration across `Baseline`, `Tiered` (default: `HIGH`, `MEDIUM < -0.03`, `LOW < 0.061102`, `INFO`), `Balanced (t=0.0)`, and `Confidence-Gated`.
6. **Explainability (`src/explain.py`):** `shap.TreeExplainer` mapped via `rf.classes_` index (`class_position()`) for supervised verdicts, paired with `baseline_deviation()` z-scores for anomaly-only alerts.
7. **Alert Triage & Dashboard (`src/alert_grouper.py`, `dashboard/app.py`):** 60s window / bounded-gap alert grouping (`summarize_groups()`) + 6-page Streamlit console protected by SHA-256 manifest verification (`src/security.py`).

---

## Expected Results *(Verified & In-Progress Framing for Interim Stage)*
- **Quantitative Detection Targets (Observed in `reports/eval_results.json`):**
  - Known-attack binary recall `99.94%`–`99.95%` across policies, with `Tiered` achieving `86.30%` actionable precision and `3.21%` actionable FPR (vs `68.21%` precision / `9.42%` FPR for `Baseline`).
  - Withheld `Infiltration` capture of `86.11%` (31/36 overall; 24/36 `MEDIUM` + 7/36 `LOW` under `Tiered`) vs `0.0%` for Random Forest alone, while transparently documenting Layer-7 web-attack boundaries (`6%–19%`).
- **Explainability & Triage Visualization:** Interactive per-flow SHAP attributions, z-score feature deviations, anomaly-score ruler, and compressed incident queues in Streamlit.
- **Final-Phase Verification Deliverables:** Reproducible latency benchmarking script, saved confusion matrices/per-class JSON metrics, live-verified `pytest` & Streamlit smoke pass in a clean Python 3.12/3.14 environment, and final 20-page PDF report.
