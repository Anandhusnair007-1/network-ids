# DESIGN, IMPLEMENTATION, AND EVALUATION OF A HYBRID MACHINE-LEARNING NETWORK INTRUSION DETECTION SYSTEM WITH WITHHELD-CATEGORY ANOMALY DETECTION AND EXPLAINABLE ALERT TRIAGE

**Minor Project Technical Report (Course Code: 21CSA391A)**  
**Department of Computer Science & Applications**  
**Amrita Vishwa Vidyapeetham — Amrita AHEAD Online**  
**Master of Computer Applications (MCA) — Regular, Semester 3**  

* **Candidate Name:** Anandhu S Nair  
* **Roll Number:** AA.SC.P2MCA25070089  
* **Academic Year:** 2025–2026  
* **Primary Dataset:** CIC-IDS2017 (Canadian Institute for Cybersecurity)  
* **Project Repository:** `/home/anandhu/projects/network-ids`  

---

## 2. Abstract & Keywords

### Abstract
Modern enterprise computer networks face continuous threats from sophisticated cyberattacks, including volumetric denial-of-service, lateral infiltration, and brute-force intrusions. Traditional Signature-based Network Intrusion Detection Systems (NIDS) fail to identify novel attack vectors, while purely supervised machine learning models demonstrate high accuracy only on threat categories explicitly represented in training data. This technical project designs, implements, and rigorously evaluates a dual-engine Hybrid Network Intrusion Detection System combining a supervised Random Forest multiclass classifier (200 estimators) with an unsupervised Isolation Forest anomaly detector, developed upon the benchmark CIC-IDS2017 dataset (2,830,743 raw network flows; 2,522,362 deduplicated flows).

To rigorously examine whether unsupervised anomaly detection can bridge the zero-day visibility gap, a controlled withheld-category experiment was executed: four attack categories—Infiltration, Web Attack Brute Force, Web Attack XSS, and Web Attack SQL Injection ($N = 2,179$ flows)—were entirely withheld from supervised training and reserved solely for evaluation. The Isolation Forest was trained strictly on benign traffic, and its decision threshold ($t = 0.061102$) was calibrated exclusively on a validation split to eliminate data leakage. The hybrid system incorporates SHAP (Shapley Additive exPlanations) TreeExplainer for per-flow feature attribution and a sliding-window Alert Grouper to mitigate Security Operations Center (SOC) alert fatigue, wrapped in an interactive 5-page Streamlit security dashboard.

Empirical evaluation on a test split of 504,037 network flows demonstrates that the supervised Random Forest attains near-optimal performance on known attacks (Macro-F1 = 0.9345, Binary Recall = 99.94%, Binary Precision = 98.75%, False Positive Rate = 0.26%). In the withheld-category experiment, the Random Forest was completely blind to Infiltration attacks (0.0% detection; 36/36 classified as BENIGN), whereas the Isolation Forest successfully flagged 31 of 36 Infiltration flows (86.11% detection rate). However, on HTTP-layer web attacks, the Isolation Forest detected only 5.03% of Brute Force, 2.76% of XSS, and 0.0% of SQL Injection flows, establishing that statistical transport/network flow features cannot discern malicious payloads without deep application-layer inspection. Furthermore, incorporating the anomaly detector into the hybrid pipeline caused the overall false positive rate to surge from 0.26% to 9.42% on the test split, generating 38,405 additional false alerts. To counteract this operational burden, the Alert Grouper demonstrated a 99.56% compression ratio in alert triage volume. Latency benchmarking revealed per-flow inference costs of 5.59 microseconds for Random Forest and 15.79 microseconds for the complete hybrid pipeline (~63,330 flows/sec). This project provides a transparent, reproducible assessment of hybrid machine learning in production network defense, delineating its tangible strengths and operational boundaries.

**Keywords:** Network Intrusion Detection System (NIDS), Hybrid Machine Learning, Random Forest, Isolation Forest, CIC-IDS2017, Withheld-Category Experiment, SHAP Explainability, Alert Fatigue Mitigation, False Positive Trade-Off.

---

## 3. Introduction & Problem Statement

### 3.1 Context & Background
Computer networks represent the foundational infrastructure for enterprise operations, cloud computing, and e-governance. Concurrently, malicious network activities have expanded in frequency and automated sophistication. Distributed Denial-of-Service (DDoS) botnets, automated password brute-forcing, remote code execution, and stealthy lateral infiltration campaigns constantly probe network perimeters. Network Intrusion Detection Systems (NIDS) serve as a primary line of perimeter defense, monitoring traffic telemetry to detect unauthorized, anomalous, or malicious operations.

### 3.2 Problem Statement
Commercial and enterprise NIDS deployments rely overwhelmingly on deterministic signature-matching engines such as Snort, Suricata, and Zeek. While signature matching delivers deterministic fidelity with false positive rates typically below 0.1%, it suffers from inherent architectural blindness:
1. **Zero-Day Incompetence:** Signature engines cannot detect zero-day exploits, novel attack techniques, or polymorphic evasion variants for which no signature has been authored.
2. **Supervised ML Closed-World Pitfall:** Supervised machine learning algorithms (Random Forests, Gradient Boosting, Deep Neural Networks) achieve near-perfect scores on benchmark test sets. However, when deployed in real networks, they operate under a closed-world assumption: traffic is forced into classes seen during training. When an unmodeled attack appears, the model misclassifies it (predominantly as benign).
3. **Black-Box Opacity:** High-capacity machine learning models fail to explain *why* a particular flow was flagged, forcing human analysts to perform tedious manual packet inspection.
4. **The False-Alarm Dilemma of Anomaly Detection:** While unsupervised anomaly detection can theoretically catch novel deviations, pure anomaly detectors suffer from severe false alarm rates, triggering thousands of spurious alerts per hour and inducing SOC analyst alert fatigue.

---

## 4. Motivation, Objectives & Research Questions

### 4.1 Motivation
The motivation of this project is to build an empirically grounded, realistic hybrid intrusion detection framework that harmonizes the high-precision categorization of supervised learning with the exploratory safety net of unsupervised anomaly detection, supported by explainability and alert compression.

### 4.2 Key Project Objectives
1. **Audit & Preprocess CIC-IDS2017:** Eliminate missing cells, infinite values, socket identifiers, and 308,381 duplicate records across 2.83M raw flows.
2. **Execute Withheld-Category Split:** Withhold four attack families (Infiltration, Web Attack Brute Force, Web Attack XSS, Web Attack SQL Injection) completely from supervised training to benchmark novel threat visibility.
3. **Construct Dual-Engine Detection Pipeline:** Train a 200-tree balanced Random Forest and a benign-only Isolation Forest with validation-calibrated decision thresholds.
4. **Develop Tiered Hybrid Logic:** Design multi-tier alert severities (HIGH, MEDIUM, LOW, INFO) to manage operational workflows.
5. **Implement Explainability & Alert Triage:** Integrate SHAP TreeExplainer for per-flow feature attribution and a sliding-window Alert Grouper to mitigate alert fatigue.
6. **Deliver Interactive SOC Dashboard:** Build a modular 6-page Streamlit interface for live prediction, triage, explainability, alert history, and anomaly inspection.

### 4.3 Research Questions
* **RQ1 (Supervised Fidelity):** How effectively does the Random Forest classifier identify known attack categories represented in its training data across multiclass and binary metrics?
* **RQ2 (Novel Category Detection):** Can an unsupervised Isolation Forest trained strictly on benign traffic successfully flag attack categories withheld from supervised training?
* **RQ3 (Hybrid Trade-Off & Cost):** Does the hybrid architecture improve held-out attack detection compared to a classifier-only baseline, and what exact false-positive cost does it introduce?
* **RQ4 (Operational Triage & Utility):** How effectively do SHAP explanations and sliding-window alert grouping support alert investigation and mitigate analyst alert fatigue?

---

## 5. Background & Literature Review

### 5.1 Machine Learning in Intrusion Detection
Supervised ensemble decision trees, notably Random Forests (Breiman, 2001), have emerged as the premier tabular classification algorithm in cybersecurity benchmarks. By constructing an ensemble of decorrelated decision trees using bagging and random feature subspaces, Random Forests achieve high expressive capacity while minimizing overfitting variance. Ahmad et al. (2021) and Sarhan et al. (2021) benchmarked multiple machine learning paradigms across contemporary datasets, demonstrating that tree-based ensembles consistently outperform deep feedforward neural networks and support vector machines on tabular flow data in both F1-score and inference latency.

### 5.2 Anomaly Detection via Isolation Forests
Isolation Forest (Liu, Ting, & Zhou, 2008) operates on a distinct, computationally efficient principle: rather than constructing profiles of normal clusters or estimating parametric density functions (such as Gaussian Mixture Models or Kernel Density Estimation), it explicitly isolates anomalies. Because anomalies are "few and different," they possess shorter average path lengths in randomized binary isolation trees (iTrees). An anomaly score is derived from the normalized expectation of tree depth across an ensemble of iTrees.

### 5.3 Explainable AI (XAI) in Cybersecurity
Deploying black-box machine learning in high-stakes operational security creates severe trust and verification deficits. Lundberg & Lee (2017) formalized SHAP (Shapley Additive exPlanations), grounded in cooperative game theory, which assigns each feature an additive importance value representing its marginal contribution to the prediction. Lundberg et al. (2020) subsequently introduced TreeExplainer, enabling exact, polynomial-time calculation of Shapley values for tree ensembles, rendering per-flow explainability computationally viable for Random Forests.

---

## 6. Existing IDS Approaches & Limitations

| Paradigm | Known Attack Detection | Novel Attack Detection | FPR / False Alarms | Explainability |
| :--- | :--- | :--- | :--- | :--- |
| **Signature-Based (Snort/Suricata)** | Very High (Deterministic) | Zero (Blind to Unseen) | Extremely Low (< 0.1%) | High (Rule Definition) |
| **Supervised ML (RF/XGBoost)** | High to Very High (> 98%) | Extremely Low (Closed-World) | Low (0.2% - 1.0%) | Opaque without XAI |
| **Anomaly-Only (One-Class/IF)** | Moderate (Unlabeled) | Moderate (Flags Deviations) | High (5% - 15%) | Poor (Single Distance Metric) |
| **Proposed Hybrid System** | Very High (RF 99.9% Recall) | Selective (Flags Structural Deviations) | Controlled via Tiered Triage | High (SHAP + Anomaly Evidence) |

---

## 7. Proposed System & Architecture

The architecture of the hybrid system operates as an integrated, modular pipeline:
1. **Ingestion & Preprocessing Engine:** Raw flows are cleaned of arithmetic infinities, deduplicated, and stripped of non-behavioral identifiers (IPs, Ports, Flow IDs, Timestamps).
2. **Supervised Classification Engine:** 200-tree balanced Random Forest computing class probability vectors over 78 numerical features.
3. **Unsupervised Anomaly Engine:** Benign-trained Isolation Forest computing continuous anomaly depth scores.
4. **Hybrid Decision Arbiter:**
   * If RF predicts an attack $\rightarrow$ Final Label = RF Attack Class, Severity = **HIGH**.
   * If RF predicts BENIGN and IF score $< 0.061102 \rightarrow$ Final Label = **Anomaly (Unclassified)**, Severity = **MEDIUM**.
   * If RF predicts BENIGN and IF score $\ge 0.061102 \rightarrow$ Final Label = **BENIGN**, Severity = **INFO**.
5. **Alert Grouper & Triage Engine:** Sliding-window aggregator clustering repetitive alerts by label, severity, and temporal boundaries.
6. **Explainability & SOC Dashboard:** Streamlit application hosting interactive prediction, triage queues, anomaly score distributions, and SHAP TreeExplainer feature attributions.

---

## 8. Dataset Description & Data-Quality Analysis

The evaluation is conducted on the CIC-IDS2017 benchmark dataset (Sharafaldin et al., 2018). Captured from July 3 to July 7, 2017, the dataset reflects realistic background traffic mixed with execution of various attack scenarios.

### 8.1 Empirical Dataset Audit

| File Name | File Size | Raw Rows | Missing Cells | Infinite Values | Attacks Present |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `Monday-WorkingHours.csv` | 168.7 MB | 529,918 | 64 | 810 | BENIGN (100%) |
| `Tuesday-WorkingHours.csv` | 128.8 MB | 445,909 | 201 | 327 | FTP-Patator, SSH-Patator |
| `Wednesday-workingHours.csv` | 214.7 MB | 692,703 | 1,008 | 1,586 | DoS Hulk, GoldenEye, slowloris, Slowhttptest, Heartbleed |
| `Thursday-Morning-WebAttacks.csv` | 49.6 MB | 170,366 | 20 | 250 | Web Attacks (Brute Force, XSS, SQLi) |
| `Thursday-Afternoon-Infilteration.csv` | 79.3 MB | 288,602 | 18 | 396 | Infiltration (36 flows) |
| `Friday-Morning.csv` | 55.6 MB | 191,033 | 28 | 216 | Bot (1,966 flows) |
| `Friday-Afternoon-PortScan.csv` | 73.3 MB | 286,467 | 15 | 727 | PortScan (158,930 flows) |
| `Friday-Afternoon-DDos.csv` | 73.6 MB | 225,745 | 4 | 64 | DDoS (128,027 flows) |
| **Total Raw Corpus** | **883.6 MB** | **2,830,743** | **1,358** | **4,376** | **14 Attack Families + Benign** |

### 8.2 Data Cleaning & Duplicate Removal
* **Infinite & Missing Values:** 4,376 infinite values (caused by zero flow duration in rate computations) and 1,358 NaN cells were imputed with 0.0.
* **Exact Duplicate Rows:** 308,381 duplicate rows were identified and removed. Retaining duplicate rows across random train/test splits introduces artificial performance inflation.
* **Clean Unique Records:** 2,522,362 flows remaining post-deduplication.

---

## 9. Methodology & Preprocessing

### 9.1 Feature Filtering & Normalization
Five identifying socket metadata columns were dropped: `Flow ID`, `Source IP`, `Destination IP`, `Source Port`, and `Timestamp`. Retaining these features causes machine learning models to memorize IP subnets and specific ports rather than learning invariant transport behaviors. The remaining 78 statistical features were standardized using `StandardScaler`, fit strictly on the training partition.

### 9.2 Withheld Attack Category Partition
Four attack categories were entirely removed before training:
* `Infiltration` ($N = 36$ flows)
* `Web Attack – Brute Force` ($N = 1,470$ flows)
* `Web Attack – XSS` ($N = 652$ flows)
* `Web Attack – Sql Injection` ($N = 21$ flows)  
Total withheld evaluation records: **2,179 flows**.

### 9.3 Stratified Partitioning (Known Categories)
The remaining 2,520,183 known-category flows were partitioned via stratified splitting:
* **Train Split (60%):** 1,512,109 flows (1,257,890 BENIGN, 254,219 Known Attacks)
* **Validation Split (20%):** 504,037 flows (419,297 BENIGN, 84,740 Known Attacks)
* **Test Split (20%):** 504,037 flows (419,297 BENIGN, 84,740 Known Attacks)

---

## 10. Model Design & Hybrid Decision Logic

### 10.1 Supervised Random Forest Classifier
* Estimators: 200 trees (`n_estimators=200`, `n_jobs=-1`, `random_state=42`).
* Class Weighting: `class_weight='balanced'` to prevent majority class dominance.
* Inputs: 78 standardized numerical features.

### 10.2 Unsupervised Isolation Forest Anomaly Detector
* Training Set: 1,257,890 BENIGN flows exclusively.
* Contamination Parameter: 0.05.
* Threshold Calibration: Calibrated via grid sweep on the independent validation split ($N=504,037$).
* Optimal Threshold: $t = 0.061102$ (yielding Validation Precision = 0.5621, Recall = 0.5872, F1 = 0.5744).

---

## 11. Experimental Results & In-Depth Analysis

### 11.1 Random Forest Multiclass Performance on Test Split ($N=504,037$)

| Class | Precision | Recall | F1-Score | Test Support |
| :--- | :---: | :---: | :---: | :---: |
| **BENIGN** | 0.9999 | 0.9974 | 0.9987 | 419,297 |
| **Bot** | 0.3525 | 0.9744 | 0.5177 | 391 |
| **DDoS** | 0.9995 | 0.9997 | 0.9996 | 25,603 |
| **DoS GoldenEye** | 0.9898 | 0.9951 | 0.9925 | 2,057 |
| **DoS Hulk** | 0.9952 | 0.9992 | 0.9972 | 34,570 |
| **DoS Slowhttptest** | 0.9858 | 0.9943 | 0.9900 | 1,046 |
| **DoS slowloris** | 0.9944 | 0.9935 | 0.9940 | 1,077 |
| **FTP-Patator** | 0.9983 | 0.9992 | 0.9987 | 1,186 |
| **Heartbleed** | 0.6667 | 1.0000 | 0.8000 | 2 |
| **PortScan** | 0.9900 | 0.9992 | 0.9945 | 18,164 |
| **SSH-Patator** | 1.0000 | 0.9938 | 0.9969 | 644 |
| **Macro Average** | **0.9065** | **0.9951** | **0.9345** | **504,037** |
| **Weighted Average** | **0.9986** | **0.9977** | **0.9980** | **504,037** |

> **Analysis of Bot Precision (0.3525):** The Bot class achieves 97.44% recall but only 35.25% precision. Out of 1,081 flows predicted as Bot, 700 were false positives (benign flows misclassified as Bot). In CIC-IDS2017, the Ares botnet communicates over HTTP/IRC, generating flow statistics (inter-packet arrival times and window sizes) that overlap heavily with standard background web traffic.

---

### 11.2 Comparative Binary Performance: RF-Only vs. Hybrid ($N=504,037$)

| Evaluation Metric | RF-Only Baseline | Hybrid System | Operational Impact |
| :--- | :---: | :---: | :--- |
| **Binary Precision** | 98.75% (0.9875) | 68.21% (0.6821) | -30.54% (Diluted by Anomaly False Positives) |
| **Binary Recall** | 99.94% (0.9994) | 99.95% (0.9995) | +0.01% (+5 Attack Flows Caught) |
| **Binary F1-Score** | 99.34% (0.9934) | 81.08% (0.8108) | -18.26% (Severe Precision Penalty) |
| **False Positive Rate (FPR)**| 0.26% (0.0026) | 9.42% (0.0942) | **36.2x Surge in False Alarm Rate** |
| **False Alarm Count (FP)** | 1,072 flows | 39,477 flows | +38,405 Spurious Alerts |
| **True Positive Count (TP)**| 84,690 flows | 84,695 flows | +5 Flows Detected |
| **True Negative Count (TN)**| 418,225 flows | 379,820 flows | 38,405 Benign Flows Misflagged |
| **Total Alerts Generated** | 85,762 alerts | 124,172 alerts | +44.8% Increase in Triage Volume |

---

### 11.3 Withheld-Category Experiment Results ($N=2,179$)

| Withheld Attack Category | Total Flows | RF Detected (Misclassified) | IF Detected (Anomaly Score < 0.0611) | Hybrid Detected | Empirical Finding |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Infiltration** | 36 | 0 (0.00%) | 31 (86.11%) | **31 (86.11%)** | RF 100% blind (BENIGN); IF successfully flagged anomaly. |
| **Web Attack – Brute Force** | 1,470 | 69 (4.69%) | 74 (5.03%) | **143 (9.73%)** | Transport flow features mimic normal web browsing. |
| **Web Attack – XSS** | 652 | 21 (3.22%) | 18 (2.76%) | **39 (5.98%)** | Malicious script payload invisible in flow statistics. |
| **Web Attack – Sql Injection**| 21 | 4 (19.05%) | 0 (0.00%) | **4 (19.05%)** | Zero structural transport anomaly. |
| **Total Withheld Corpus** | **2,179** | **94 (4.31%)** | **123 (5.64%)** | **217 (9.96%)** | **Hybrid achieves 2.3x higher detection than RF.** |

> **Critical Note on Infiltration Detection (86.11%):** Although the Isolation Forest caught 31 of 36 Infiltration flows, the sample size ($N = 36$) is statistically small (Wilson 95% CI: [71.3%, 93.9%]). Furthermore, flagging a flow as anomalous is not identical to identifying an attack: it merely signifies deviation from normal benign profiles.

---

### 11.4 Latency & Throughput Benchmarking (10,000 Flows)

| Operational Stage | Total Batch Latency | Latency per Flow | Estimated Throughput |
| :--- | :---: | :---: | :---: |
| **StandardScaler Transformation** | 1.20 ms | 0.12 $\mu$s/flow | ~8,306,000 flows/sec |
| **Random Forest Inference** | 78.62 ms | 7.86 $\mu$s/flow | ~127,200 flows/sec |
| **Isolation Forest Decision Function** | 66.84 ms | 6.68 $\mu$s/flow | ~149,600 flows/sec |
| **Complete Hybrid Decision Pipeline** | 151.00 ms | 15.10 $\mu$s/flow | ~66,220 flows/sec |

### 11.5 Alert Grouping & Fatigue Mitigation
* **Note:** the figures in this section were measured before `summarize_groups()` was corrected to keep ungrouped alerts in the analyst queue, and the original 99.56% compression is therefore not reproducible. The current method yields 8% on a 2,000-flow upload with random IPs and 2-second spacing, and 95% on a shuffled sample with batch-wide grouping (see `README.md`). Reduction depends on traffic.

### 11.6 API Load Test (`POST /v1/score`)

Measured on the development host (AMD Ryzen 7 6800H, Python 3.12.16) against a single uvicorn worker running `api.main:app` directly, not in Docker. Each row ran for 15 s with `persist=false` and real `test.parquet` flows (seed 42), over loopback. All 1,744 requests returned HTTP 200; there were no errors or timeouts.

| Batch (flows) | Concurrency | Req/s | Flows/s | p50 | p95 | p99 |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 1 | 24.2 | 24 | 41 ms | 44 ms | 46 ms |
| 1 | 8 | 27.1 | 27 | 295 ms | 362 ms | 393 ms |
| 100 | 1 | 20.2 | 2,023 | 46 ms | 58 ms | 60 ms |
| 100 | 8 | 18.1 | 1,810 | 441 ms | 509 ms | 543 ms |
| 1,000 | 1 | 8.8 | 8,769 | 114 ms | 118 ms | 123 ms |
| 1,000 | 4 | 8.7 | 8,654 | 464 ms | 527 ms | 560 ms |
| 1,000 | 16 | 7.7 | 7,684 | 2,071 ms | 2,307 ms | 2,378 ms |

* Throughput does not rise with concurrency; latency grows roughly in proportion to it, so one worker effectively serves one scoring request at a time. Scale with more workers or replicas.
* End-to-end API throughput (about 8,800 flows/s at best) is far below the in-process figure in 11.4 (about 66,000 flows/s) because of JSON parsing, validation, drift assessment and HTTP overhead. Per-flow calls (about 41 ms) should be batched.
* Resident memory of the worker was about 624 MB after the run.
* Not covered: the Docker image (no Docker daemon available), SQLite write load (`persist=false`), the CSV endpoint, rate limiting under load, multi-worker deployment and long soak runs.

---

## 12. Synthesis of Research Questions

* **RQ1 (Supervised Fidelity):** Confirmed. Random Forest attains high fidelity (Macro-F1 = 0.9345, Binary Recall = 99.94%, FPR = 0.26%). However, minority classes with high benign overlap (Bot precision = 0.3525) demonstrate sensitivity limitations.
* **RQ2 (Novel Category Detection):** Partially Confirmed. Isolation Forest detected 86.11% of unseen Infiltration attacks due to aberrant transport flow characteristics. However, it achieved only 0% to 5% detection on web attacks, proving statistical flow features cannot detect application-layer payload exploits.
* **RQ3 (Hybrid Trade-Off & Cost):** Confirmed. The hybrid architecture elevated novel attack detection from 4.31% to 9.96% (and from 0% to 86.11% on Infiltration). However, it caused the false positive rate on known traffic to surge 36.2-fold (0.26% to 9.42%), generating 38,405 extra false alarms.
* **RQ4 (Operational Triage & Utility):** Partially confirmed. SHAP TreeExplainer provided clear feature attributions for alerts. The AlertGrouper reduced the analyst queue by 8%–95% depending on traffic structure, so the benefit is traffic-dependent.

---

## 13. Testing & Software Verification

The test suite in `tests/test_hybrid.py` executes 10 automated test cases via `pytest`:
1. `test_predict_returns_correct_count`: Verifies 1:1 batch mapping.
2. `test_known_attack_is_high`: Asserts RF attacks are assigned HIGH severity.
3. `test_benign_rf_anomaly_if_is_medium`: Asserts RF Benign + IF anomaly yields MEDIUM severity.
4. `test_both_benign_is_info`: Asserts RF Benign + IF normal yields INFO severity.
5. `test_predict_df_adds_columns`: Asserts dataframe output schema integrity.
6. `test_no_group_below_min`: Asserts alerts $< 5$ flows do not form groups.
7. `test_single_group_above_min`: Asserts alert grouping threshold behavior.
8. `test_groups_to_dataframe`: Validates conversion to analytical dataframe.
9. `test_multiple_groups`: Asserts distinct label/severity cluster separation.
10. `test_empty_dataframe`: Asserts graceful handling of empty inputs.  
**Result:** **10 passed in 0.30s (100% pass rate).**

---

## 14. References

1. Ahmad, Z., Shahid Khan, A., Che Wai Shiang, C., Abdullah, J., & Ahmad, F. (2021). Network intrusion detection system: A systematic study of machine learning and deep learning approaches. *Transactions on Emerging Telecommunications Technologies*, 32(1), e4150. https://doi.org/10.1002/ett.4150
2. Breiman, L. (2001). Random Forests. *Machine Learning*, 45(1), 5–32. https://doi.org/10.1023/A:1010933404324
3. Engelen, G., Rimmer, V., & Joosen, W. (2021). Troubleshooting an Incomplete Machine Learning Anomaly Detection Pipeline: A Case Study on CIC-IDS2017. In *Proceedings of the 2021 ACM Workshop on Artificial Intelligence and Security (AISEC '21)*, 25–35. https://doi.org/10.1145/3474369.3486866
4. Lanvin, N., Sommer, R., & Cavalli, A. (2023). Errors in the CICIDS2017 dataset and their impact on ML-based network intrusion detection. *IEEE Transactions on Network and Service Management*, 20(3), 2874–2888.
5. Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. In *2008 Eighth IEEE International Conference on Data Mining (ICDM)*, 413–422. https://doi.org/10.1109/ICDM.2008.17
6. Lundberg, S. M., & Lee, S. I. (2017). A Unified Approach to Interpreting Model Predictions. In *Advances in Neural Information Processing Systems 30 (NeurIPS 2017)*, 4765–4774.
7. Lundberg, S. M., Erion, G., Chen, H., DeGrave, A., Prutkin, J. M., Nair, B., Katz, R., Himmelfarb, J., Bansal, N., & Lee, S. I. (2020). From local explanations to global understanding with explainable AI for trees. *Nature Machine Intelligence*, 2(1), 56–67. https://doi.org/10.1038/s42256-019-0138-9
8. Rosay, A., Carlier, F., & Leroux, B. (2022). Improving CIC-IDS-2017 with new missing flows and realistic evaluation. In *2022 IEEE 47th Conference on Local Computer Networks (LCN)*, 345–352. https://doi.org/10.1109/LCN53696.2022.9843644
9. Sarhan, M., Layeghy, S., & Portmann, M. (2021). Evaluating machine learning algorithms for network intrusion detection using standard data sets. *IEEE Access*, 9, 87638–87654. https://doi.org/10.1109/ACCESS.2021.3089456
10. Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. In *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP 2018)*, 108–116. https://doi.org/10.5220/0006639801080116
