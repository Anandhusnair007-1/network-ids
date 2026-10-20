"""
dashboard/app.py
================
Streamlit dashboard for the Hybrid Network IDS.

Pages
-----
1.  Overview          – dataset stats + model metrics cards
2.  Live Prediction   – upload a CSV / use test split, run hybrid detector
3.  Alert Triage      – grouped alert table with severity filter
4.  Explainability    – SHAP waterfall / bar plots for selected flows
5.  Anomaly Analysis  – anomaly score distribution + withheld-category results
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

# Allow importing from src/
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from alert_grouper import AlertGrouper, groups_to_dataframe  # noqa: E402
from hybrid import HybridDetector  # noqa: E402

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Network IDS · Hybrid ML Dashboard",
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

/* Cards */
div[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 16px;
}

/* Alert severity badges */
.badge-HIGH   { background:#ff4b4b22; color:#ff4b4b; border:1px solid #ff4b4b55;
                padding:2px 10px; border-radius:20px; font-size:0.8rem; font-weight:600; }
.badge-MEDIUM { background:#ffa50022; color:#ffa500; border:1px solid #ffa50055;
                padding:2px 10px; border-radius:20px; font-size:0.8rem; font-weight:600; }
.badge-INFO   { background:#238636; color:#3fb950; border:1px solid #238636;
                padding:2px 10px; border-radius:20px; font-size:0.8rem; font-weight:600; }

/* Section headers */
h2 { color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 8px; }
h3 { color: #79c0ff; }

/* Upload area */
.uploadedFile { background: #161b22 !important; border-radius: 8px; }

/* Tables */
.stDataFrame { border-radius: 8px; overflow: hidden; }
</style>
""", unsafe_allow_html=True)

# ── Constants ─────────────────────────────────────────────────────────────────
DATA_DIR    = Path("data/processed")
MODELS_DIR  = Path("models")
REPORTS_DIR = Path("reports")

SEVERITY_COLORS = {"HIGH": "🔴", "MEDIUM": "🟡", "INFO": "🟢"}


# ── Cached loaders ────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner="Loading models…")
def load_detector() -> HybridDetector:
    return HybridDetector.load()


@st.cache_data(show_spinner="Loading features…")
def load_features() -> list[str]:
    with open(DATA_DIR / "features.json") as f:
        return json.load(f)


@st.cache_data(show_spinner="Loading label map…")
def load_label_map() -> dict[int, str]:
    with open(DATA_DIR / "label_map.json") as f:
        return {int(k): v for k, v in json.load(f).items()}


@st.cache_data(show_spinner="Loading eval results…")
def load_eval() -> dict | None:
    p = REPORTS_DIR / "eval_results.json"
    if not p.exists():
        return None
    with open(p) as f:
        return json.load(f)


@st.cache_data(show_spinner="Loading test split…")
def load_test_sample(n: int = 2000) -> pd.DataFrame:
    df = pd.read_parquet(DATA_DIR / "test.parquet")
    return df.sample(min(n, len(df)), random_state=42).reset_index(drop=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Network IDS")
    st.caption("Hybrid ML · CIC-IDS2017")
    st.divider()
    page = st.radio(
        "Navigation",
        ["📊 Overview", "🔍 Live Prediction", "🚨 Alert Triage",
         "💡 Explainability", "📈 Anomaly Analysis"],
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("Anandhu S Nair · Minor Project 21CSA391A")


# ── Helper: run detector on a DataFrame ───────────────────────────────────────
def run_detector(df: pd.DataFrame) -> pd.DataFrame:
    detector     = load_detector()
    feature_cols = load_features()
    # Only keep columns that exist in the dataframe
    available = [c for c in feature_cols if c in df.columns]
    missing   = [c for c in feature_cols if c not in df.columns]
    if missing:
        st.warning(f"{len(missing)} feature columns missing from uploaded file – filling with 0.")
        for c in missing:
            df[c] = 0.0
    return detector.predict_df(df, feature_cols)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1 – OVERVIEW
# ─────────────────────────────────────────────────────────────────────────────
if page == "📊 Overview":
    st.title("📊 IDS Dashboard — Overview")

    eval_data = load_eval()
    label_map = load_label_map()

    # --- Model metrics cards -------------------------------------------------
    col1, col2, col3, col4 = st.columns(4)
    rf_eval  = eval_data["known_attack_test"]["rf_only"]  if eval_data else {}
    hyb_eval = eval_data["known_attack_test"]["hybrid"]   if eval_data else {}

    with col1:
        st.metric("RF Macro-F1",      f"{rf_eval.get('f1', 'N/A')}")
    with col2:
        st.metric("Hybrid Macro-F1",  f"{hyb_eval.get('f1', 'N/A')}")
    with col3:
        st.metric("RF False Positive Rate",     f"{rf_eval.get('fpr', 'N/A')}")
    with col4:
        st.metric("Hybrid False Positive Rate", f"{hyb_eval.get('fpr', 'N/A')}")

    st.divider()

    # --- Withheld experiment -------------------------------------------------
    if eval_data:
        w = eval_data.get("withheld_experiment", {})
        st.subheader("🧪 Withheld-Category Experiment")
        wc1, wc2, wc3 = st.columns(3)
        with wc1:
            st.metric("Withheld Rows", f"{w.get('total_withheld_rows', 0):,}")
        with wc2:
            st.metric("IF Detection Rate", f"{w.get('if_detection_rate', 0):.1%}")
        with wc3:
            st.metric("Hybrid Detection Rate", f"{w.get('hybrid_detection_rate', 0):.1%}")

        per_label = w.get("per_label", {})
        if per_label:
            rows = []
            for lbl, stats in per_label.items():
                rows.append({
                    "Attack Family": lbl,
                    "Total Flows": stats["total"],
                    "RF Detected": stats["rf_detected"],
                    "IF Detected": stats["if_detected"],
                    "IF Rate": f"{stats['if_detected'] / max(stats['total'], 1):.1%}",
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("Run `python src/evaluate_hybrid.py` to populate model metrics.")

    # --- Dataset overview ----------------------------------------------------
    st.divider()
    st.subheader("📦 Dataset Overview — CIC-IDS2017")
    dataset_info = {
        "File": [
            "Monday (BENIGN)",
            "Tuesday (FTP/SSH Patator)",
            "Wednesday (DoS family + Heartbleed)",
            "Thursday AM (Web Attacks – withheld)",
            "Thursday PM (Infiltration – withheld)",
            "Friday AM (Bot)",
            "Friday PM (PortScan)",
            "Friday PM (DDoS)",
        ],
        "Rows": [529918, 445909, 692703, 170366, 288602, 191033, 286467, 225745],
        "Attack Family": [
            "–", "FTP-Patator, SSH-Patator",
            "DoS Hulk, GoldenEye, Slowloris, Slowhttptest, Heartbleed",
            "Web Attack BF / XSS / SQLi ⛔", "Infiltration ⛔",
            "Bot", "PortScan", "DDoS",
        ],
    }
    st.dataframe(pd.DataFrame(dataset_info), use_container_width=True, hide_index=True)
    st.caption("⛔ = withheld from supervised training")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2 – LIVE PREDICTION
# ─────────────────────────────────────────────────────────────────────────────
elif page == "🔍 Live Prediction":
    st.title("🔍 Live Prediction")

    source = st.radio(
        "Input source",
        ["Use test split sample", "Upload CSV"],
        horizontal=True,
    )

    if source == "Use test split sample":
        n = st.slider("Number of rows to sample", 100, 5000, 1000, step=100)
        df_input = load_test_sample(n)
        st.caption(f"Loaded {len(df_input):,} rows from test split.")
    else:
        uploaded = st.file_uploader("Upload a CIC-IDS2017-format CSV", type="csv")
        if not uploaded:
            st.info("Upload a CSV file to begin.")
            st.stop()
        df_input = pd.read_csv(uploaded, low_memory=False)
        df_input.columns = df_input.columns.str.strip()

    if st.button("▶ Run Hybrid Detector", type="primary"):
        with st.spinner("Running detector …"):
            results = run_detector(df_input.copy())

        st.success(f"Processed {len(results):,} flows.")

        # Summary cards
        n_attacks  = int((results["severity"] == "HIGH").sum())
        n_anomalies= int((results["severity"] == "MEDIUM").sum())
        n_benign   = int((results["severity"] == "INFO").sum())

        c1, c2, c3 = st.columns(3)
        with c1: st.metric("🔴 Known Attacks",  n_attacks)
        with c2: st.metric("🟡 Anomalies",      n_anomalies)
        with c3: st.metric("🟢 Benign",          n_benign)

        # Show prediction table
        display_cols = ["final_label", "severity", "rf_label",
                        "rf_confidence", "anomaly_score"]
        if "Label" in results.columns:
            display_cols.insert(0, "Label")

        st.dataframe(
            results[display_cols].rename(columns={
                "final_label":    "Final Label",
                "severity":       "Severity",
                "rf_label":       "RF Label",
                "rf_confidence":  "RF Confidence",
                "anomaly_score":  "Anomaly Score",
                "Label":          "True Label",
            }),
            use_container_width=True,
            height=400,
        )

        st.session_state["pred_results"] = results


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 3 – ALERT TRIAGE
# ─────────────────────────────────────────────────────────────────────────────
elif page == "🚨 Alert Triage":
    st.title("🚨 Alert Triage")

    if "pred_results" not in st.session_state:
        st.info("Run the detector on the **Live Prediction** page first.")
        st.stop()

    results  = st.session_state["pred_results"]
    grouper  = AlertGrouper(min_alerts=5)
    groups   = grouper.group(results)
    groups_df = groups_to_dataframe(groups)

    if groups_df.empty:
        st.warning("No alert groups formed (not enough flows per category).")
        st.stop()

    sev_filter = st.multiselect(
        "Filter by severity",
        ["HIGH", "MEDIUM", "INFO"],
        default=["HIGH", "MEDIUM"],
    )
    filtered = groups_df[groups_df["severity"].isin(sev_filter)]

    st.caption(f"Showing {len(filtered):,} alert groups.")
    st.dataframe(
        filtered.rename(columns={
            "group_id": "ID", "label": "Label", "severity": "Severity",
            "count": "Flows", "avg_confidence": "Avg RF Confidence",
            "avg_anomaly_score": "Avg Anomaly Score",
            "window_start": "From", "window_end": "To",
        }),
        use_container_width=True,
        height=500,
    )


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 4 – EXPLAINABILITY
# ─────────────────────────────────────────────────────────────────────────────
elif page == "💡 Explainability":
    st.title("💡 SHAP Explainability")

    try:
        import shap
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        st.error("SHAP is not installed. Run: `pip install shap`")
        st.stop()

    if "pred_results" not in st.session_state:
        st.info("Run the detector on the **Live Prediction** page first.")
        st.stop()

    results      = st.session_state["pred_results"]
    detector     = load_detector()
    feature_cols = load_features()

    # Only explain attack / anomaly rows for clarity
    alert_rows = results[results["severity"].isin(["HIGH", "MEDIUM"])]
    if alert_rows.empty:
        st.info("No alert rows to explain.")
        st.stop()

    idx = st.selectbox(
        "Select a row to explain",
        options=alert_rows.index[:100].tolist(),
        format_func=lambda i: f"Row {i} — {alert_rows.loc[i, 'final_label']}",
    )

    row_df = results.loc[[idx], feature_cols]
    X_row  = detector.scaler.transform(
        row_df.to_numpy(dtype=np.float32)
    )

    with st.spinner("Computing SHAP values …"):
        explainer   = shap.TreeExplainer(detector.rf)
        shap_values = explainer.shap_values(X_row)

    # Multiclass: show SHAP for the predicted class
    pred_code  = detector.rf.predict(X_row)[0]
    shap_slice = shap_values[pred_code][0]   # shape: (n_features,)

    st.subheader(f"SHAP explanation — predicted: `{detector.label_map[pred_code]}`")
    st.caption(f"Anomaly score: {results.loc[idx, 'anomaly_score']:.4f}  |  "
               f"Severity: {results.loc[idx, 'severity']}")

    # Bar chart of top 20 features
    feat_imp = pd.Series(np.abs(shap_slice), index=feature_cols).nlargest(20)
    fig, ax  = plt.subplots(figsize=(8, 5), facecolor="#0d1117")
    ax.set_facecolor("#161b22")
    bars = ax.barh(feat_imp.index[::-1], feat_imp.values[::-1], color="#58a6ff")
    ax.set_xlabel("| SHAP value |", color="#e6edf3")
    ax.set_title("Top 20 Feature Importances (SHAP)", color="#e6edf3")
    ax.tick_params(colors="#e6edf3")
    ax.spines[:].set_color("#21262d")
    st.pyplot(fig)

    # Waterfall if available
    try:
        expl_obj = shap.Explanation(
            values=shap_slice,
            base_values=explainer.expected_value[pred_code],
            data=X_row[0],
            feature_names=feature_cols,
        )
        fig2, ax2 = plt.subplots(facecolor="#0d1117")
        shap.plots.waterfall(expl_obj, max_display=15, show=False)
        st.pyplot(fig2)
    except Exception:
        pass   # waterfall not always available in all SHAP versions


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 5 – ANOMALY ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
elif page == "📈 Anomaly Analysis":
    st.title("📈 Anomaly Score Analysis")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        st.error("Matplotlib not available.")
        st.stop()

    eval_data = load_eval()

    if "pred_results" in st.session_state:
        results = st.session_state["pred_results"]
        st.subheader("Anomaly Score Distribution")

        fig, ax = plt.subplots(figsize=(10, 4), facecolor="#0d1117")
        ax.set_facecolor("#161b22")

        benign  = results.loc[results["severity"] == "INFO",   "anomaly_score"]
        attacks = results.loc[results["severity"] == "HIGH",   "anomaly_score"]
        anomaly = results.loc[results["severity"] == "MEDIUM", "anomaly_score"]

        if not benign.empty:
            ax.hist(benign,  bins=50, alpha=0.6, label="BENIGN",  color="#3fb950")
        if not attacks.empty:
            ax.hist(attacks, bins=50, alpha=0.6, label="Attacks", color="#ff4b4b")
        if not anomaly.empty:
            ax.hist(anomaly, bins=50, alpha=0.8, label="Anomaly (IF only)", color="#ffa500")

        ax.set_xlabel("Anomaly Score (lower = more anomalous)", color="#e6edf3")
        ax.set_ylabel("Count", color="#e6edf3")
        ax.set_title("Isolation Forest Anomaly Score Distribution", color="#e6edf3")
        ax.legend(facecolor="#21262d", labelcolor="#e6edf3")
        ax.tick_params(colors="#e6edf3")
        ax.spines[:].set_color("#21262d")
        st.pyplot(fig)
    else:
        st.info("Run the detector on the **Live Prediction** page to see score distribution.")

    # Withheld experiment chart
    if eval_data:
        st.divider()
        st.subheader("Withheld-Category Detection Comparison")
        w = eval_data.get("withheld_experiment", {})
        per_label = w.get("per_label", {})
        if per_label:
            rows = []
            for lbl, stats in per_label.items():
                rows.append({
                    "Family": lbl,
                    "Total": stats["total"],
                    "RF": stats["rf_detected"],
                    "IF": stats["if_detected"],
                })
            cmp_df = pd.DataFrame(rows).set_index("Family")

            fig2, ax2 = plt.subplots(figsize=(10, 4), facecolor="#0d1117")
            ax2.set_facecolor("#161b22")
            x = range(len(cmp_df))
            w_bar = 0.35
            ax2.bar([i - w_bar/2 for i in x], cmp_df["RF"], width=w_bar,
                    label="RF detected",    color="#58a6ff", alpha=0.8)
            ax2.bar([i + w_bar/2 for i in x], cmp_df["IF"], width=w_bar,
                    label="IF detected",    color="#ffa500", alpha=0.8)
            ax2.set_xticks(list(x))
            ax2.set_xticklabels(cmp_df.index, rotation=20, ha="right", color="#e6edf3")
            ax2.set_ylabel("Flows Detected", color="#e6edf3")
            ax2.set_title("RF vs Isolation Forest on Withheld Attack Families", color="#e6edf3")
            ax2.legend(facecolor="#21262d", labelcolor="#e6edf3")
            ax2.tick_params(colors="#e6edf3")
            ax2.spines[:].set_color("#21262d")
            st.pyplot(fig2)
