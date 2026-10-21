"""
dashboard/app.py
================
Enterprise Security Operations Dashboard for the Hybrid Network IDS.

Features & Operations
---------------------
1. Overview           – Dataset statistics, model evaluation KPIs, artifact integrity status.
2. Live Prediction    – Secure CSV upload / test sample evaluation with schema validation.
3. Alert Triage       – Sliding-window and bounded sequential alert grouping to combat fatigue.
4. Explainability     – Local SHAP TreeExplainer feature attributions for classifier alerts.
5. Anomaly Analysis   – Isolation Forest score distributions and withheld-attack benchmarks.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from alert_grouper import AlertGrouper, groups_to_dataframe
from config import (
    DATA_DIR,
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_ROWS,
    REPORTS_DIR,
)
from hybrid import HybridDetector
from policy import (
    BaselinePolicy,
    CalibratedThresholdPolicy,
    TieredSeverityPolicy,
)
from security import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ManifestError,
)
from validator import (
    InputValidator,
    MissingFeatureError,
    OversizedInputError,
    ValidationError,
)

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Enterprise Network IDS · Hybrid Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

.stApp { background: #0d1117; color: #e6edf3; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #161b22 0%, #0d1117 100%);
    border-right: 1px solid #21262d;
}

/* Metric Cards */
div[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 16px;
}

/* Severity Badges */
.badge-HIGH   { background:#ff4b4b22; color:#ff4b4b; border:1px solid #ff4b4b55;
                padding:3px 10px; border-radius:20px; font-size:0.8rem; font-weight:600; }
.badge-MEDIUM { background:#ffa50022; color:#ffa500; border:1px solid #ffa50055;
                padding:3px 10px; border-radius:20px; font-size:0.8rem; font-weight:600; }
.badge-LOW    { background:#388bfd22; color:#58a6ff; border:1px solid #388bfd55;
                padding:3px 10px; border-radius:20px; font-size:0.8rem; font-weight:600; }
.badge-INFO   { background:#238636; color:#3fb950; border:1px solid #238636;
                padding:3px 10px; border-radius:20px; font-size:0.8rem; font-weight:600; }

/* Headers */
h2 { color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 8px; }
h3 { color: #79c0ff; }

/* Status callout */
.status-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 16px;
}
</style>
""", unsafe_allow_html=True)


# ── Cached Loaders & Singletons ───────────────────────────────────────────────

@st.cache_resource(show_spinner="Verifying artifact integrity & loading models…")
def load_detector_with_policy(policy_mode: str) -> HybridDetector:
    if policy_mode == "tiered":
        policy = TieredSeverityPolicy(deep_threshold=-0.03, marginal_threshold=0.061102)
    elif policy_mode == "balanced":
        policy = CalibratedThresholdPolicy(target_threshold=0.0)
    else:
        policy = BaselinePolicy()

    try:
        return HybridDetector.load(policy=policy)
    except ArtifactIntegrityError as e:
        st.error(f"🚨 CRITICAL SECURITY ERROR: Model integrity verification failed!\n\n{e}")
        st.stop()
    except (ArtifactNotFoundError, ManifestError) as e:
        st.error(f"⚠️ Model startup error: Required artifacts are missing or malformed.\n\n{e}")
        st.stop()


@st.cache_data(show_spinner="Loading canonical feature schema…")
def load_features() -> list[str]:
    with open(DATA_DIR / "features.json", "r", encoding="utf-8") as f:
        return json.load(f)


@st.cache_data(show_spinner="Loading label dictionary…")
def load_label_map() -> dict[int, str]:
    with open(DATA_DIR / "label_map.json", "r", encoding="utf-8") as f:
        return {int(k): v for k, v in json.load(f).items()}


@st.cache_data(show_spinner="Loading evaluation benchmarks…")
def load_eval() -> dict | None:
    p = REPORTS_DIR / "eval_results.json"
    if not p.exists():
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


@st.cache_data(show_spinner="Sampling evaluation dataset…")
def load_test_sample(n: int = 1000) -> pd.DataFrame:
    df = pd.read_parquet(DATA_DIR / "test.parquet")
    return df.sample(min(n, len(df)), random_state=42).reset_index(drop=True)


# ── Sidebar Navigation & Operational Policy Controls ──────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ Enterprise NIDS")
    st.caption("Hybrid ML Platform · CIC-IDS2017")
    st.divider()

    page = st.radio(
        "Navigation",
        ["📊 Overview", "🔍 Live Prediction", "🚨 Alert Triage",
         "💡 Explainability", "📈 Anomaly Analysis"],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("### ⚙️ Operational Detection Policy")

    policy_label = st.selectbox(
        "Active Arbitration Policy",
        [
            "Baseline (Production Default)",
            "Tiered Severity (SOC Recommended)",
            "Balanced (t = 0.0)",
        ],
        index=0,
        help="Selects the arbitration policy used by the Hybrid Decision Core.",
    )

    # Map label to internal mode
    if "Tiered" in policy_label:
        policy_mode = "tiered"
    elif "Balanced" in policy_label:
        policy_mode = "balanced"
    else:
        policy_mode = "baseline"

    # Display operational policy context
    with st.expander("ℹ️ Policy Operational Trade-off"):
        if policy_mode == "baseline":
            st.markdown("""
            **Baseline Mode:**
            - Known Attacks: **HIGH**
            - Anomaly ($s(x) < 0.0611$): **MEDIUM**
            - Benign: **INFO**
            - *Trade-off:* Maximum novel anomaly recall (86.1% Infiltration caught), but higher baseline false alarm rate (~9.4% FPR).
            """)
        elif policy_mode == "tiered":
            st.markdown(r"""
            **Tiered Severity Mode (SOC Recommended):**
            - Known Attacks: **HIGH**
            - Deep Anomaly ($s(x) < -0.03$): **MEDIUM** (High-priority on-call queue, ~3.2% FPR)
            - Marginal Anomaly ($-0.03 \le s(x) < 0.0611$): **LOW** (Telemetry / Threat Hunting queue)
            - *Trade-off:* Prevents SOC alert fatigue while retaining full visibility for threat hunters.
            """)
        elif policy_mode == "balanced":
            st.markdown("""
            **Balanced Threshold Mode:**
            - Decision threshold set to $t = 0.0$.
            - Reduces false alarms by 45% (FPR ~5.2%, Precision ~79.4%) while catching 77.8% of novel Infiltration flows.
            """)

    st.divider()
    st.caption("🔒 SHA-256 Artifact Verification: Active")


# ── Helper: Execute Hybrid Inference on DataFrame ─────────────────────────────

def run_detector(df: pd.DataFrame, policy_mode: str, fill_missing: bool = False) -> pd.DataFrame:
    detector = load_detector_with_policy(policy_mode)
    feature_cols = load_features()

    validator = InputValidator(
        feature_cols=feature_cols,
        max_rows=MAX_UPLOAD_ROWS,
        fill_missing=fill_missing,
        allow_extra_columns=True,
    )
    # Perform strict schema validation
    validated_df = validator.validate_df(df)

    # Run high-throughput vectorized prediction
    return detector.predict_df(validated_df, feature_cols, validate=False)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1 – OVERVIEW & INTEGRITY STATUS
# ─────────────────────────────────────────────────────────────────────────────
if page == "📊 Overview":
    st.title("📊 Platform Overview & System Health")

    # System Integrity Banner
    st.markdown(f"""
    <div class="status-card">
        <strong>🔒 System Integrity & Operational Posture:</strong><br/>
        • <strong>Model Artifacts:</strong> Verified via SHA-256 Manifest (<code>models/manifest.json</code>)<br/>
        • <strong>Inference Engine:</strong> Vectorized NumPy Dual-Engine Pipeline<br/>
        • <strong>Active Policy:</strong> <code>{policy_label}</code>
    </div>
    """, unsafe_allow_html=True)

    eval_data = load_eval()

    # Benchmark KPI Cards
    col1, col2, col3, col4 = st.columns(4)
    rf_eval  = eval_data["known_attack_test"]["rf_only"] if eval_data else {}
    hyb_eval = eval_data["known_attack_test"]["hybrid"] if eval_data else {}

    with col1:
        st.metric("RF Precision (Test)", f"{rf_eval.get('precision', 0):.2%}")
    with col2:
        st.metric("RF Recall (Test)", f"{rf_eval.get('recall', 0):.2%}")
    with col3:
        st.metric("RF Baseline FPR", f"{rf_eval.get('fpr', 0):.2%}")
    with col4:
        st.metric("Hybrid Test FPR", f"{hyb_eval.get('fpr', 0):.2%}")

    st.divider()

    # Withheld-Category Experiment Results
    if eval_data:
        w = eval_data.get("withheld_experiment", {})
        st.subheader("🧪 Novel Threat Benchmark (Withheld-Category Experiment)")
        wc1, wc2, wc3 = st.columns(3)
        with wc1:
            st.metric("Total Withheld Records", f"{w.get('total_withheld_rows', 0):,}")
        with wc2:
            st.metric("Isolation Forest Novel Detection", f"{w.get('if_detection_rate', 0):.1%}")
        with wc3:
            st.metric("Hybrid Novel Detection", f"{w.get('hybrid_detection_rate', 0):.1%}")

        per_label = w.get("per_label", {})
        if per_label:
            rows = []
            for lbl, stats in per_label.items():
                rows.append({
                    "Threat Category": lbl,
                    "Total Flows": stats["total"],
                    "RF Detected (Unseen)": stats["rf_detected"],
                    "Isolation Forest Flagged": stats["if_detected"],
                    "Novel Detection Rate": f"{stats['if_detected'] / max(stats['total'], 1):.1%}",
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("📦 Evaluated Corpus — CIC-IDS2017 Composition")
    dataset_info = {
        "File Partition": [
            "Monday-WorkingHours.pcap_ISCX.csv",
            "Tuesday-WorkingHours.pcap_ISCX.csv",
            "Wednesday-workingHours.pcap_ISCX.csv",
            "Thursday-Morning-WebAttacks.pcap_ISCX.csv",
            "Thursday-Afternoon-Infilteration.pcap_ISCX.csv",
            "Friday-Morning.pcap_ISCX.csv",
            "Friday-Afternoon-PortScan.pcap_ISCX.csv",
            "Friday-Afternoon-DDos.pcap_ISCX.csv",
        ],
        "Raw Flows": [529918, 445909, 692703, 170366, 288602, 191033, 286467, 225745],
        "Attack Scenario": [
            "Normal Baseline (BENIGN)",
            "FTP-Patator, SSH-Patator",
            "DoS Hulk, GoldenEye, slowloris, Slowhttptest, Heartbleed",
            "Web Attacks (Brute Force, XSS, SQLi) — [Withheld Evaluation]",
            "Infiltration — [Withheld Evaluation]",
            "Botnet (Ares)",
            "PortScan",
            "DDoS (LOIC)",
        ],
    }
    st.dataframe(pd.DataFrame(dataset_info), use_container_width=True, hide_index=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2 – LIVE PREDICTION & TELEMETRY VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
elif page == "🔍 Live Prediction":
    st.title("🔍 Telemetry Ingestion & Live Hybrid Prediction")

    st.caption(f"Active Decision Policy: **{policy_label}**")

    source = st.radio(
        "Input Data Source",
        ["Sample Held-Out Test Split", "Upload Telemetry CSV"],
        horizontal=True,
    )

    df_input: pd.DataFrame | None = None
    allow_zero_fill = False

    if source == "Sample Held-Out Test Split":
        n = st.slider("Select batch size", 100, 5000, 1000, step=100)
        df_input = load_test_sample(n)
        st.info(f"Loaded {len(df_input):,} flow records from test partition.")
    else:
        st.markdown(f"**Safety Limits:** Maximum {MAX_UPLOAD_ROWS:,} rows · Maximum {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
        uploaded = st.file_uploader("Upload Network Flow CSV (CIC-IDS2017 format)", type=["csv"])

        allow_zero_fill = st.checkbox(
            "Auto-fill missing feature columns with 0.0 (Fallback Mode)",
            value=False,
            help="If checked, missing features are imputed with zeros instead of raising a schema error.",
        )

        if uploaded:
            if uploaded.size > MAX_UPLOAD_BYTES:
                st.error(f"❌ Upload rejected: File size ({uploaded.size / (1024 * 1024):.1f} MB) exceeds limit of {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
                st.stop()

            try:
                df_input = pd.read_csv(uploaded, low_memory=False)
                df_input.columns = df_input.columns.astype(str).str.strip()
            except Exception as e:
                st.error(f"❌ Failed to parse uploaded CSV: {e}")
                st.stop()
        else:
            st.info("Upload a network flow CSV file or switch to 'Sample Held-Out Test Split'.")
            st.stop()

    if df_input is not None and st.button("▶ Run Hybrid Inspection", type="primary"):
        with st.spinner("Executing strict schema validation and vectorized inference…"):
            try:
                results = run_detector(df_input.copy(), policy_mode, fill_missing=allow_zero_fill)
            except MissingFeatureError as e:
                st.error(f"❌ Schema Validation Error: {e}\n\n*Tip: Check the 'Auto-fill missing feature columns' option to run in fallback mode.*")
                st.stop()
            except OversizedInputError as e:
                st.error(f"❌ DoS Protection Triggered: {e}")
                st.stop()
            except ValidationError as e:
                st.error(f"❌ Telemetry Validation Error: {e}")
                st.stop()
            except Exception as e:
                st.error(f"❌ Unexpected inference error: {e}")
                st.stop()

        st.success(f"Successfully processed {len(results):,} network flows under policy: **{policy_label}**.")

        # Summary Metric Cards
        n_high   = int((results["severity"] == "HIGH").sum())
        n_medium = int((results["severity"] == "MEDIUM").sum())
        n_low    = int((results["severity"] == "LOW").sum())
        n_info   = int((results["severity"] == "INFO").sum())

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("🔴 HIGH (Known Attacks)", n_high)
        with c2:
            st.metric("🟡 MEDIUM (Deep Anomalies)", n_medium)
        with c3:
            st.metric("🔵 LOW (Marginal Anomalies)", n_low)
        with c4:
            st.metric("🟢 INFO (Normal Traffic)", n_info)

        # Result Table View
        cols_to_show = ["final_label", "severity", "rf_label", "rf_confidence", "anomaly_score"]
        if "Label" in results.columns:
            cols_to_show.insert(0, "Label")

        st.dataframe(
            results[cols_to_show].rename(columns={
                "Label": "True Label",
                "final_label": "Final Classification",
                "severity": "Assigned Severity",
                "rf_label": "RF Classifier Output",
                "rf_confidence": "RF Confidence",
                "anomaly_score": "Isolation Score",
            }),
            use_container_width=True,
            height=400,
        )

        st.session_state["pred_results"] = results
        st.session_state["active_policy"] = policy_label


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 3 – ALERT TRIAGE & FATIGUE MITIGATION
# ─────────────────────────────────────────────────────────────────────────────
elif page == "🚨 Alert Triage":
    st.title("🚨 Alert Incident Triage")

    if "pred_results" not in st.session_state:
        st.info("Execute detection on the **Live Prediction** page to generate alert queues.")
        st.stop()

    results = st.session_state["pred_results"]
    active_policy = st.session_state.get("active_policy", "Baseline")

    st.caption(f"Triage Queue generated under: **{active_policy}**")

    # Filter by severity
    available_severities = sorted(list(results["severity"].unique()))
    default_selected = [s for s in ["HIGH", "MEDIUM", "LOW"] if s in available_severities]

    sev_filter = st.multiselect(
        "Filter Triage Queue by Severity",
        options=available_severities,
        default=default_selected if default_selected else available_severities,
    )

    filtered_flows = results[results["severity"].isin(sev_filter)]

    # Alert Grouper execution
    grouper = AlertGrouper(min_alerts=5, max_index_gap=50, include_benign=False)
    groups = grouper.group(filtered_flows)
    groups_df = groups_to_dataframe(groups)

    raw_alert_count = len(filtered_flows[filtered_flows["severity"] != "INFO"])
    grouped_count = len(groups)

    # Triage KPI compression cards
    tc1, tc2, tc3 = st.columns(3)
    with tc1:
        st.metric("Raw Alerts in Queue", f"{raw_alert_count:,}")
    with tc2:
        st.metric("Consolidated Incident Groups", f"{grouped_count:,}")
    with tc3:
        comp_ratio = ((1 - (grouped_count / max(raw_alert_count, 1))) * 100) if raw_alert_count > 0 else 0
        st.metric("Alert Compression Ratio", f"{comp_ratio:.1f}%")

    if groups_df.empty:
        st.warning("No consolidated alert groups formed (flow counts below group threshold).")
    else:
        st.dataframe(
            groups_df.rename(columns={
                "group_id": "Incident ID",
                "label": "Threat Label",
                "severity": "Severity",
                "count": "Flow Volume",
                "avg_confidence": "Mean Confidence",
                "avg_anomaly_score": "Mean Anomaly Score",
                "window_start": "Start Boundary",
                "window_end": "End Boundary",
            }),
            use_container_width=True,
            height=500,
        )


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 4 – EXPLAINABILITY (SHAP TREEEXPLAINER)
# ─────────────────────────────────────────────────────────────────────────────
elif page == "💡 Explainability":
    st.title("💡 Explainable AI — SHAP Attributions")

    try:
        import matplotlib
        import shap
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        st.error("SHAP / Matplotlib is not available.")
        st.stop()

    if "pred_results" not in st.session_state:
        st.info("Execute detection on the **Live Prediction** page first.")
        st.stop()

    results = st.session_state["pred_results"]
    detector = load_detector_with_policy("baseline")
    feature_cols = load_features()

    alert_rows = results[results["severity"].isin(["HIGH", "MEDIUM", "LOW"])]
    if alert_rows.empty:
        st.info("No alert records present in current session to explain.")
        st.stop()

    idx = st.selectbox(
        "Select an Alert Flow to Explain",
        options=alert_rows.index[:100].tolist(),
        format_func=lambda i: f"Flow #{i} — {alert_rows.loc[i, 'final_label']} [{alert_rows.loc[i, 'severity']}]",
    )

    row_df = results.loc[[idx], feature_cols]
    X_row = detector.scaler.transform(row_df.to_numpy(dtype=np.float32))

    with st.spinner("Computing exact Shapley values via TreeExplainer…"):
        explainer = shap.TreeExplainer(detector.rf)
        shap_values = explainer.shap_values(X_row)

    pred_code = detector.rf.predict(X_row)[0]
    shap_slice = shap_values[pred_code][0]

    st.subheader(f"Classifier Evidence — Predicted Class: `{detector.label_map.get(pred_code, 'Unknown')}`")
    st.caption(f"Isolation Forest Anomaly Score: **{results.loc[idx, 'anomaly_score']:.4f}** | Assigned Severity: **{results.loc[idx, 'severity']}**")

    # Bar chart of top 20 features
    feat_imp = pd.Series(np.abs(shap_slice), index=feature_cols).nlargest(20)
    fig, ax = plt.subplots(figsize=(8, 5), facecolor="#0d1117")
    ax.set_facecolor("#161b22")
    bars = ax.barh(feat_imp.index[::-1], feat_imp.values[::-1], color="#58a6ff")
    ax.set_xlabel("| SHAP Importance Value |", color="#e6edf3")
    ax.set_title("Top 20 Decisive Features (SHAP)", color="#e6edf3")
    ax.tick_params(colors="#e6edf3")
    ax.spines[:].set_color("#21262d")
    st.pyplot(fig)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 5 – ANOMALY SCORE ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
elif page == "📈 Anomaly Analysis":
    st.title("📈 Anomaly Score Distribution Analysis")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        st.error("Matplotlib is not available.")
        st.stop()

    eval_data = load_eval()

    if "pred_results" in st.session_state:
        results = st.session_state["pred_results"]
        st.subheader("Current Session Anomaly Score Distribution")

        fig, ax = plt.subplots(figsize=(10, 4), facecolor="#0d1117")
        ax.set_facecolor("#161b22")

        benign  = results.loc[results["severity"] == "INFO", "anomaly_score"]
        attacks = results.loc[results["severity"] == "HIGH", "anomaly_score"]
        anomalies = results.loc[results["severity"].isin(["MEDIUM", "LOW"]), "anomaly_score"]

        if not benign.empty:
            ax.hist(benign, bins=40, alpha=0.5, label="Normal Traffic (INFO)", color="#3fb950", density=True)
        if not attacks.empty:
            ax.hist(attacks, bins=40, alpha=0.5, label="Known Attacks (HIGH)", color="#ff4b4b", density=True)
        if not anomalies.empty:
            ax.hist(anomalies, bins=40, alpha=0.7, label="Anomalies (MEDIUM/LOW)", color="#ffa500", density=True)

        ax.axvline(x=0.061102, color="#ffffff", linestyle="--", label="Baseline Threshold (0.0611)")
        ax.axvline(x=-0.03, color="#58a6ff", linestyle=":", label="Tiered Strict Threshold (-0.03)")

        ax.set_xlabel("Isolation Forest Anomaly Score (Lower = More Anomalous)", color="#e6edf3")
        ax.set_ylabel("Density", color="#e6edf3")
        ax.set_title("Density Distribution Across Traffic Classifications", color="#e6edf3")
        ax.legend(facecolor="#21262d", labelcolor="#e6edf3")
        ax.tick_params(colors="#e6edf3")
        ax.spines[:].set_color("#21262d")
        st.pyplot(fig)
    else:
        st.info("Execute detection on the **Live Prediction** page to visualize current session score distributions.")
