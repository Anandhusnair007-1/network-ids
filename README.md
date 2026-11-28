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
        │  Random Forest (200 T)  │       │ Isolation Forest (200 T)│
        │ - 11 classes (10 attacks)│       │ - Trained on BENIGN only│
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
   - Trained on BENIGN plus 10 attack types: DoS (Hulk, GoldenEye, slowloris, Slowhttptest), DDoS, PortScan, Bot, Heartbleed, FTP-Patator and SSH-Patator. Infiltration and the three Web attacks are withheld on purpose (see section 3).

3. **Semi-Supervised Anomaly Detector (`src/train_iforest.py`)**:
   - Isolation Forest (200 estimators, `contamination=0.05`; the operating threshold is tuned on the validation split, not taken from `contamination`) trained strictly on `BENIGN` traffic.
   - Flags structural and geometric departures in flow timing, packet sizes, and inter-arrival distributions.

4. **Arbitration Policy Engine (`src/policy.py`)**:
   - Decouples raw model outputs from operational SOC actionability.
   - Provides hot-swappable policies to trade off threat capture against analyst alert fatigue.

5. **Alert Grouper & Triage Engine (`src/alert_grouper.py`)**:
   - Groups alerts by `(label, severity)` and, when the input carries `Source IP` / `Destination IP` columns, by those too. Uses fixed 60-second windows when a `Timestamp` column exists, otherwise capture-order proximity or whole-batch grouping.
   - Alerts in groups below the minimum size stay individual alerts; the console reports them separately, so the queue-reduction figure is not inflated. Real reduction depends on your traffic: on a synthetic 2,000-flow upload with random IPs and 2-second spacing it was 8%, on a shuffled sample with batch-wide grouping 95%.

6. **Explainability (`src/hybrid.py`, `dashboard/app.py`)**:
   - Integrates SHAP `TreeExplainer` to calculate local Shapley attributions for any suspicious flow.
   - Identifies the exact top 20 flow features driving anomalous classifications.

7. **Cryptographic Model Integrity (`src/security.py`)**:
   - Computes SHA-256 digests using buffered streaming reads.
   - Enforces pre-deserialization validation against `models/manifest.json` using constant-time comparison (`hmac.compare_digest`) before any pickle deserialization.

---

## 2. Detection Policies & Operational Trade-Offs

The platform supports four arbitration policies (a fourth, *Confidence-gated*, is experimental). Every figure below is produced by `make evaluate` and stored in `reports/eval_results.json` under `policy_comparison`; the dashboard reads it from there.

Measured on the 504,037-flow test split ("actionable" = High + Medium alerts, i.e. what pages an analyst):

| Policy | Precision | Recall | False alarm rate | Alerts | Infiltration flagged |
|---|---|---|---|---|---|
| Tiered (recommended) | 86.3% | 99.94% | 3.21% | 98,130 (+26,042 Low) | 66.7% (86.1% incl. Low) |
| Baseline | 68.2% | 99.95% | 9.42% | 124,172 | 86.1% |
| Balanced (t = 0) | 79.6% | 99.94% | 5.19% | 106,433 | 77.8% |
| Confidence-gated | 86.0% | 99.95% | 3.28% | 98,459 | 86.1% |

| Policy | Decision Rule | Primary Strength | Operational Trade-Off | Recommended Use |
|---|---|---|---|---|
| **Baseline Policy** | Threat if $RF \neq \text{BENIGN}$ or $s_{\text{IF}} < 0.0611$ | Maximum detection recall (99.95%) on test splits; flags subtle deviations. | High false alarm rate (9.42% FPR); triggers on noisy network edges. | Forensic replay, high-security enclave monitoring. |
| **Tiered Severity** *(Recommended)* | Strict: $s_{\text{IF}} < -0.03 \to$ `MEDIUM`<br>Marginal: $-0.03 \le s_{\text{IF}} \le 0.0611 \to$ `LOW`<br>Normal: $s_{\text{IF}} > 0.0611 \to$ `INFO` | Distinguishes deep anomalies from marginal noise; preserves Infiltration detection without flooding high-priority queues. | SOC workflow must triage `LOW` and `MEDIUM` priority queues separately. | 24/7 Enterprise SOC triage and incident response. |
| **Balanced (t = 0)** | Threat if $RF \neq \text{BENIGN}$ or $s_{\text{IF}} < 0.0$ | Cuts false alarms to 5.2% FPR (79.6% precision) while still flagging 77.8% of Infiltration. | Fewer novel threats than Baseline. | Automated SIEM ingestion with a single sensitivity knob. |

---

## 3. Empirical Benchmarks & Evaluation Methodology

### Dataset & Preprocessing Pipeline
- **Benchmark Dataset**: CIC-IDS2017 (Canadian Institute for Cybersecurity), containing 2,830,743 raw network flows across 8 capture days.
- **Cleaning & Hygiene**:
  - Removed socket-level artifacts (`Flow ID`, `Source IP`, `Destination IP`, `Source Port`, `Timestamp`) before training to eliminate shortcut learning and IP memorization.
  - Known limitation: the 78-column schema still contains 8 constant columns (`Bwd PSH Flags`, `Bwd URG Flags`, and the six `*Bulk*` features) and a duplicate (`Fwd Header Length.1`). They are harmless to tree models; removing them requires retraining and would change the manifest.
  - Stripped leading/trailing whitespace from header columns and sanitized infinite/null values.
  - Final processed split: 60% train / 20% validation / 20% held-out test (504,037 flows), stratified, known categories only.
  - Known limitation: the split is a stratified random split, so flows from the same capture day appear in train, validation and test. Reported metrics may be optimistic compared with a split by capture day or a different network; this was not tested.

### Held-Out Test Evaluation ($N = 504,037$)

All metrics measured against the unseen test split:

| Pipeline | Accuracy | Precision | Recall | F1 Score | False Positive Rate | Total Alerts Raised |
|---|---|---|---|---|---|---|
| **RF-Only Baseline** | 99.78% | 0.9875 | 0.9994 | 0.9934 | 0.26% | 85,762 |
| **Hybrid Baseline** | 92.16% | 0.6821 | 0.9995 | 0.8108 | 9.42% | 124,172 |

### Zero-Day / Withheld Attack Experiment ($N = 2,179$)

To simulate novel, zero-day threat families, four attack categories were **completely withheld from Random Forest training** and presented only at test time:

| Withheld Attack Family | Total Flows | RF Alone Detected | Isolation Forest Detected | Combined Hybrid Detections |
|---|---|---|---|---|
| **Infiltration** | 36 | 0 (0.0%) | 31 (86.1%) | **31 (86.1%)** |
| **Web Attack – Brute Force** | 1,470 | 69 (4.7%) | 74 (5.0%) | **143 (9.7%)** |
| **Web Attack – XSS** | 652 | 21 (3.2%) | 18 (2.8%) | **39 (6.0%)** |
| **Web Attack – SQL Injection** | 21 | 4 (19.0%) | 0 (0.0%) | **4 (19.0%)** |
| **Total Unseen Categories** | **2,179** | **94 (4.31%)** | **123 (5.64%)** | **217 (9.96%)** |

> **Reading these numbers**: only the Infiltration result is strong, and it rests on 36 flows. The three Web attack types are detected at roughly 6-19%, because they look like ordinary web browsing at flow level; treat them as out of scope for this model and cover them with a WAF. Zero-day capability here means "unusual flow statistics", not general novel-attack detection.

> **Key Finding**: Infiltration exploits (lateral port scans and privilege escalations) evade supervised classifiers with 93.5% median confidence because their flow statistics mimic standard workstation behavior. The semi-supervised Isolation Forest successfully identified 86.1% of these evasive flows as statistical anomalies.

### Inference Performance

Measured by `make benchmark` (`reports/benchmarks/benchmark_results.json`; AMD Ryzen 7 6800H, Python 3.12.16, scikit-learn 1.9.1, seed 42, warm-up excluded, model load timed separately). Median hybrid pipeline latency (scaler + Random Forest + Isolation Forest + policy) by batch size:
- **1 flow**: 76.8 ms per call (fixed per-call cost of the 200-tree ensembles; batch for throughput).
- **1,000 flows**: 100.3 us per flow (~9,970 flows/s).
- **10,000 flows**: 15.10 us per flow (~66,200 flows/s).
- **50,000 flows**: 10.13 us per flow (~98,700 flows/s).
- **Peak process memory**: 2,113 MB RSS for the whole benchmark run (it also loads the full test split; not a serving figure).
- **Serving memory**: about 624 MB RSS for one uvicorn worker after 1,744 scoring requests (`reports/TECHNICAL_PROJECT_REPORT.md` section 11.6).

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

`make install-dev` adds pytest and ruff. After retraining, run `make manifest` so the integrity manifest matches the new files (`make all` does this for you).

### Launching the Dashboard

```bash
make dashboard
```

Navigate to `http://localhost:8501`. The console has six pages: Overview (policy trade-offs and the novel-threat benchmark), Scan flows (sample traffic or CSV upload), Incidents, Investigate flow (SHAP evidence, deviation from baseline, anomaly-score ruler), Alert history (stored incidents and analyst verdicts) and Detector health (integrity, score distribution, threshold sensitivity). It makes no external network requests, and Streamlit telemetry is disabled in `.streamlit/config.toml`.

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

# Full pipeline: preprocess, train both models, regenerate the manifest, evaluate
make all

# Re-register model files in the SHA-256 manifest (run once, right after training)
make manifest
```

---

## 8. Release Verification Checklist

| Verification Gate | Requirement | Status | Evidence |
|---|---|---|---|
| **Cryptographic Integrity** | All model artifacts match signed SHA-256 manifest prior to loading. | **PASSED** | Verified via `src/security.py` (4/4 artifacts authentic). |
| **Unit & Security Tests** | 100% pass rate on unit, security, tamper-detection and regression tests. | **PASSED** | 89/89 tests passing in `tests/`. |
| **Code Hygiene & Linting** | Zero syntax errors, no unused imports, PEP-8 compliant. | **PASSED** | `ruff check` passed across all modules. |
| **Dependency Auditing** | No broken dependencies or version conflicts in environment. | **PASSED** | `pip check` confirmed zero broken requirements. |
| **Dashboard Schema Validation** | Enforced 78-column schema, 50k row limit, error handling. | **PASSED** | Tested in `tests/test_dashboard_integration.py`. |
| **Explainability Validation** | SHAP TreeExplainer integration produces valid attributions. | **PASSED** | Verified with synthetic and real flow inputs. |
| **Reproducibility** | `make evaluate` reproduces the published metrics from the stored models. | **PASSED** | Re-run: RF precision 0.9875 / recall 0.9994, hybrid FPR 0.0942, withheld detections 94 / 123 / 217. Retraining from raw CSVs (`make all`) was not re-run in this audit. |

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

## Production layer

Beyond the dashboard, the repo includes a secured scoring API (`api/`), an incident database, SIEM export (CEF syslog and
signed webhook), input-drift monitoring, Ed25519-signed model manifests, a dashboard login, a folder ingestor, a Dockerfile
with compose, and CI. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), [docs/SECURITY.md](docs/SECURITY.md) and
[docs/RUNBOOK.md](docs/RUNBOOK.md). This is a pilot-ready system, not a finished product: it has not scored live traffic,
the thresholds were tuned on CIC-IDS2017 only, and the Docker image has not been built or run here. API load was measured on one uvicorn worker (about 8,800 flows/s at 1,000-flow batches; see `reports/TECHNICAL_PROJECT_REPORT.md` section 11.6).
