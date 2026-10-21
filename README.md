# Enterprise Hybrid Network Intrusion Detection Platform (NIDS)

An enterprise-grade hybrid Network Intrusion Detection System combining high-throughput supervised classification (Random Forest), semi-supervised anomaly detection (Isolation Forest), dynamic arbitration policies, explainable AI (SHAP TreeExplainer), and temporal alert triage.

Designed for statistical network flow telemetry, this platform achieves sub-millisecond inference latencies, zero-tolerance input validation, and cryptographic model integrity verification.

---

## 1. System Architecture

```
                  ┌────────────────────────────────────────┐
                  │    Ingested Flow Telemetry (CSV)       │
                  └───────────────────┬────────────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │   InputValidator Layer    │
                        │ - Schema enforcement (78) │
                        │ - Max 50k rows / 50 MB    │
                        │ - NaN / Inf sanitization  │
                        └─────────────┬─────────────┘
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
        ┌─────────────────────────┐       ┌─────────────────────────┐
        │  Random Forest (200 T)  │       │ Isolation Forest (0.01) │
        │ - 15 attack classes     │       │ - Trained on BENIGN only│
        │ - Multiclass label & p  │       │ - Anomaly decision score│
        └────────────┬────────────┘       └────────────┬────────────┘
                     │                                 │
                     └────────────────┬────────────────┘
                                      │
                                      ▼
                      ┌───────────────────────────────┐
                      │    Arbitration Policy Engine  │
                      │ - Baseline Policy (Recall)    │
                      │ - Tiered Severity (Balanced)  │
                      │ - Calibrated Threshold        │
                      └───────────────┬───────────────┘
                                      │
                                      ▼
                      ┌───────────────────────────────┐
                      │    Alert Grouper & Triage     │
                      │ - Sliding window / gap index  │
                      │ - Incident compression        │
                      └───────────────┬───────────────┘
                                      │
                       ┌──────────────┴──────────────┐
                       ▼                             ▼
        ┌─────────────────────────────┐  ┌─────────────────────────┐
        │     Streamlit SOC Console   │  │   SHAP TreeExplainer    │
        │ - Real-time investigation   │  │ - Local flow attribution│
        │ - Integrity & policy audit  │  │ - Analyst verification  │
        └─────────────────────────────┘  └─────────────────────────┘
```

### Core Components

1. **Input Validation & DoS Protection (`src/validator.py`)**:
   - Strictly enforces the 78 canonical CIC-IDS2017 numeric features.
   - Rejects batches exceeding memory safety limits (default: 50,000 flows or 50 MB).
   - Sanitizes `NaN`, `+Inf`, and `-Inf` values to prevent estimator numerical instability.
   - Disallows unexpected string or non-numeric types by default, with an explicit opt-in fallback mode for zero-imputation.

2. **Supervised Classifier (`src/train_rf.py`)**:
   - 200-tree Random Forest classifier optimized with balanced class weighting.
   - Outputs predicted attack class and maximum class posterior probability ($p_{\text{RF}}$).
   - Trained across 11 known attack families: DoS (Hulk, GoldenEye, slowloris, Slowhttptest), DDoS, PortScan, Botnet, FTP-Patator, and SSH-Patator.

3. **Semi-Supervised Anomaly Detector (`src/train_iforest.py`)**:
   - Isolation Forest (200 estimators, 1% contamination) trained strictly on clean `BENIGN` network traffic.
   - Flags structural and geometric departures in flow timing, packet sizes, and inter-arrival distributions.

4. **Arbitration Policy Engine (`src/policy.py`)**:
   - Decouples raw model outputs from operational SOC actionability.
   - Provides hot-swappable policies to trade off threat capture against analyst alert fatigue.

5. **Alert Grouper & Triage Engine (`src/alert_grouper.py`)**:
   - Temporal and index-gap sliding window clustering for consecutive alerts sharing `(src_ip, dst_ip, attack_type)`.
   - Aggregates high-frequency alert bursts into actionable incident packages, reducing alert fatigue by up to 90%.

6. **Explainability (`src/hybrid.py`, `dashboard/app.py`)**:
   - Integrates SHAP `TreeExplainer` to calculate local Shapley attributions for any suspicious flow.
   - Identifies the exact top 20 flow features driving anomalous classifications.

7. **Cryptographic Model Integrity (`src/security.py`)**:
   - Computes SHA-256 digests using buffered streaming reads.
   - Enforces pre-deserialization validation against `models/manifest.json` using constant-time comparison (`hmac.compare_digest`) before any pickle deserialization.

---

## 2. Detection Policies & Operational Trade-Offs

The platform supports three distinct arbitration policies:

| Policy | Decision Rule | Primary Strength | Operational Trade-Off | Recommended Use |
|---|---|---|---|---|
| **Baseline Policy** | Threat if $RF \neq \text{BENIGN}$ or $s_{\text{IF}} < 0.0$ | Maximum detection recall (99.95%) on test splits; flags subtle deviations. | High false alarm rate (9.42% FPR); triggers on noisy network edges. | Forensic replay, high-security enclave monitoring. |
| **Tiered Severity** *(Recommended)* | Strict: $s_{\text{IF}} < -0.03 \to$ `MEDIUM`<br>Marginal: $-0.03 \le s_{\text{IF}} \le 0.0611 \to$ `LOW`<br>Normal: $s_{\text{IF}} > 0.0611 \to$ `INFO` | Distinguishes deep anomalies from marginal noise; preserves Infiltration detection without flooding high-priority queues. | SOC workflow must triage `LOW` and `MEDIUM` priority queues separately. | 24/7 Enterprise SOC triage and incident response. |
| **Calibrated Threshold** | Threat if $RF \neq \text{BENIGN}$ or $s_{\text{IF}} < t_{\text{tuned}}$ | Single knob calibration ($t = 0.061102$) maximizing validation $F_1$. | Elevated FPR when operated at strict thresholds. | Automated SIEM ingestion with custom sensitivity filters. |

---

## 3. Empirical Benchmarks & Evaluation Methodology

### Dataset & Preprocessing Pipeline
- **Benchmark Dataset**: CIC-IDS2017 (Canadian Institute for Cybersecurity), containing 2,830,743 raw network flows across 8 capture days.
- **Cleaning & Hygiene**:
  - Removed socket-level artifacts (`Flow ID`, `Source IP`, `Destination IP`, `Timestamp`) during training to eliminate shortcut learning and IP memorization.
  - Dropped zero-variance features (`Bwd PSH Flags`, `Fwd URG Flags`, etc.).
  - Stripped leading/trailing whitespace from header columns and sanitized infinite/null values.
  - Final processed split: 80% Train/Val (stratified), 20% Held-Out Test (504,037 flows).

### Held-Out Test Evaluation ($N = 504,037$)

All metrics measured against the unseen test split:

| Pipeline | Accuracy | Precision | Recall | F1 Score | False Positive Rate | Total Alerts Raised |
|---|---|---|---|---|---|---|
| **RF-Only Baseline** | 99.80% | 0.9875 | 0.9994 | 0.9934 | 0.26% | 85,762 |
| **Hybrid Baseline** | 98.24% | 0.6821 | 0.9995 | 0.8108 | 9.42% | 124,172 |

### Zero-Day / Withheld Attack Experiment ($N = 2,179$)

To simulate novel, zero-day threat families, four attack categories were **completely withheld from Random Forest training** and presented only at test time:

| Withheld Attack Family | Total Flows | RF Alone Detected | Isolation Forest Detected | Combined Hybrid Detections |
|---|---|---|---|---|
| **Infiltration** | 36 | 0 (0.0%) | 31 (86.1%) | **31 (86.1%)** |
| **Web Attack – Brute Force** | 1,470 | 69 (4.7%) | 74 (5.0%) | **143 (9.7%)** |
| **Web Attack – XSS** | 652 | 21 (3.2%) | 18 (2.8%) | **39 (6.0%)** |
| **Web Attack – SQL Injection** | 21 | 4 (19.0%) | 0 (0.0%) | **4 (19.0%)** |
| **Total Unseen Categories** | **2,179** | **94 (4.31%)** | **123 (5.64%)** | **217 (9.96%)** |

> **Key Finding**: Infiltration exploits (lateral port scans and privilege escalations) evade supervised classifiers with 93.5% median confidence because their flow statistics mimic standard workstation behavior. The semi-supervised Isolation Forest successfully identified 86.1% of these evasive flows as statistical anomalies.

### Inference Performance

Benchmarked on an Intel Xeon @ 2.20 GHz:
- **Vectorized NumPy Engine**: **12.16 microseconds per flow** (~82,204 flows/second throughput).
- **Peak Process Memory**: ~280 MB during full test set streaming evaluation.

---

## 4. Offline Dataset vs. Live Network Monitoring

> [!IMPORTANT]
> **Operational Scope Distinction**:
> This platform currently operates on **bidirectional network flow summary records** (e.g., CSV, Parquet, IPFIX, NetFlow, Zeek `conn.log`). It is **not** an inline raw packet sniffer or deep packet inspection (DPI) engine.

### Deployment Gap Analysis

To deploy this platform in a live network environment, the following upstream ingestion components must be connected:

```
[ TAP / SPAN Mirror ] ──► [ Zeek / CICFlowMeter ] ──► [ Kafka / Redis ] ──► [ Hybrid NIDS Engine ]
(Raw Ethernet Frames)     (Flow Feature Extractor)     (Stream Buffer)       (Inference & Triage)
```

1. **Flow Generation**: Upstream packet-capture probes (e.g., `Zeek`, `CICFlowMeter`, or `GoFlow`) must reassemble TCP sessions and compute flow statistics (inter-arrival times, packet length distributions, window sizes) over configurable timeouts (e.g., 120s flow active timeout).
2. **Payload Blindness**: The 78 statistical features capture network behavior but cannot inspect encrypted payload data (e.g., TLS 1.3 payloads). Payload-based attacks like SQL Injection have low statistical variance at the transport layer ($N=21$ flows in CIC-IDS2017) and require complementary WAF or host-based inspection.
3. **Flow Directionality**: Flow feature calculations depend on bidirectional flow trackers correctly identifying the initiator (client) vs. responder (server).

---

## 5. Security Architecture & Threat Model

1. **Pickle Deserialization Boundary**:
   - Model deserialization using Python `pickle` presents remote code execution (RCE) risks if artifacts are modified.
   - **Mitigation**: `src/security.py` calculates SHA-256 digests using chunked reads and verifies them against `models/manifest.json` before deserializing files.
   - **Trust Boundary Limitation**: In a standalone deployment, `models/manifest.json` is stored on the local filesystem. For production hardening, the manifest or public key must be backed by a hardware security module (HSM), signed KMS key, or mounted on a read-only filesystem volume.

2. **Denial-of-Service (DoS) Ingestion Protection**:
   - Large or malformed CSV telemetry uploads can exhaust server memory.
   - **Mitigation**: `InputValidator` enforces strict row count ceilings (default 50,000 rows) and byte-size limits (50 MB) before parsing dataframes into memory.

3. **Adversarial Flow Perturbation**:
   - Attackers may pad packet lengths or delay inter-packet arrivals to push anomaly scores into the `BENIGN` distribution.
   - **Mitigation**: The dual-model hybrid architecture forces attackers to simultaneously spoof multiclass tree boundaries and semi-supervised geometric isolation envelopes.

---

## 6. Installation & Quick Start

### Prerequisites
- Linux OS (Ubuntu 22.04 LTS / Debian 12 / RHEL 9 recommended)
- Python 3.10+ (Tested on Python 3.12.3)
- 8 GB RAM minimum (16 GB recommended for full CIC-IDS2017 dataset training)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/Anandhusnair007-1/network-ids.git
cd network-ids

# 2. Initialize virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Verify all cryptographic artifacts and run quality gates
make check
```

### Launching the Dashboard

```bash
make dashboard
```

Navigate to `http://localhost:8501` to access the SOC Console.

---

## 7. Makefile Interface & Quality Gates

The repository includes a self-contained `Makefile` enforcing release readiness:

```bash
# Automated release quality gate (integrity + lint + compile + dependencies + test suite)
make check

# Verify cryptographic SHA-256 hashes of all trained model artifacts
make verify-artifacts

# Run Ruff linter across source code, dashboard, and tests
make lint

# Execute complete unit, security, and integration test suite
make test

# Full pipeline execution from raw CSVs to evaluation report
make all
```

---

## 8. Release Verification Checklist

| Verification Gate | Requirement | Status | Evidence |
|---|---|---|---|
| **Cryptographic Integrity** | All model artifacts match signed SHA-256 manifest prior to loading. | **PASSED** | Verified via `src/security.py` (4/4 artifacts authentic). |
| **Unit & Security Tests** | 100% pass rate on unit, security, and tamper detection tests. | **PASSED** | 43/43 tests passing in `tests/`. |
| **Code Hygiene & Linting** | Zero syntax errors, no unused imports, PEP-8 compliant. | **PASSED** | `ruff check` passed across all modules. |
| **Dependency Auditing** | No broken dependencies or version conflicts in environment. | **PASSED** | `pip check` confirmed zero broken requirements. |
| **Dashboard Schema Validation** | Enforced 78-column schema, 50k row limit, error handling. | **PASSED** | Tested in `tests/test_dashboard_integration.py`. |
| **Explainability Validation** | SHAP TreeExplainer integration produces valid attributions. | **PASSED** | Verified with synthetic and real flow inputs. |
| **Reproducibility** | Full pipeline runs end-to-end via deterministic Makefile targets. | **PASSED** | Clean execution from raw data to evaluation report. |

---

## 9. Limitations & Production Roadmap

1. **Streaming Ingestion**: Future releases will replace batch CSV uploads with streaming Kafka/gRPC ingestion consumers.
2. **Standardized Model Serializers**: Transition from pickled scikit-learn models to ONNX (Open Neural Network Exchange) or Treelite runtime to eliminate Python pickle deserialization entirely.
3. **Adaptive Thresholding**: Implement continuous background estimation of background network noise to dynamically adjust $t_{\text{marginal}}$ without manual intervention.
4. **Dataset Aging**: The CIC-IDS2017 dataset reflects 2017 attack profiles; operational deployment requires continuous retraining on modern telemetry datasets (e.g., CIC-IDS2018, UNSW-NB15, or enterprise network PCAPs).

---

## 10. License & Citations

- **Dataset**: CIC-IDS2017 provided by the Canadian Institute for Cybersecurity, University of New Brunswick.
  > Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP.
