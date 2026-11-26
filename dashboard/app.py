"""
dashboard/app.py
================
SOC console for the hybrid Network IDS (Random Forest + Isolation Forest).

Pages
-----
Overview          what the system is, how each policy trades false alarms for novel-threat recall
Scan flows        run a batch (sample traffic or an uploaded CSV) through both models
Incidents         collapse alerts into incidents an analyst can work through
Investigate flow  explain one alert: classifier evidence, deviation from baseline, score ruler
Detector health   model integrity, score distribution, threshold sensitivity, operating limits

Run with ``make dashboard`` from the project root.
"""

from __future__ import annotations

import io
import json
import sys
from datetime import datetime
from pathlib import Path

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import soc_ui as ui  # noqa: E402
from auth import require_login, sidebar_status  # noqa: E402
from alert_grouper import AlertGrouper, groups_to_dataframe, summarize_groups  # noqa: E402
from config import (  # noqa: E402
    DATA_DIR,
    DB_PATH,
    DRIFT_REFERENCE_PATH,
    DST_IP_ALIASES,
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_ROWS,
    REPORTS_DIR,
    SRC_IP_ALIASES,
    pretty_label,
)
import drift as drift_mod  # noqa: E402
from explain import baseline_deviation, make_explainer, shap_attribution  # noqa: E402
from hybrid import HybridDetector  # noqa: E402
from policy import DEEP_ANOMALY_THRESHOLD, POLICY_INFO, build_policy  # noqa: E402
from security import (  # noqa: E402
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ManifestError,
    load_manifest,
    verify_all_artifacts,
)
from store import STATUSES, IncidentStore  # noqa: E402
from validator import InputValidator, ValidationError  # noqa: E402

st.set_page_config(
    page_title="Network IDS",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)
ui.inject_css()

MAX_TABLE_ROWS = 2000
MAX_UPLOAD_MB = MAX_UPLOAD_BYTES // (1024 * 1024)

MIX_LABELS = {
    "typical": "Typical traffic (about 1 in 6 flows is an attack)",
    "attack_heavy": "Attack-heavy (half the flows are attacks)",
    "novel": "Novel threats only (attack types the classifier never saw)",
}


# =============================================================================
# Loaders
# =============================================================================
def _fmt_size(n: int) -> str:
    return f"{n / 1e6:.1f} MB" if n >= 1e6 else f"{n / 1e3:.1f} KB" if n >= 1e3 else f"{n} B"


@st.cache_resource(show_spinner="Verifying model files and loading the detector…")
def _load_base() -> tuple[HybridDetector, list[dict]]:
    verified = verify_all_artifacts()  # raises on any mismatch, before anything is unpickled
    manifest = load_manifest()["artifacts"]
    detector = HybridDetector.load()
    info = [
        {
            "File": name,
            "Type": manifest[name].get("type", ""),
            "Size": _fmt_size(manifest[name].get("size_bytes", 0)),
            "SHA-256": sha[:16] + "…",
            "Status": "Verified",
        }
        for name, sha in verified.items()
    ]
    return detector, info


def get_base() -> tuple[HybridDetector, list[dict]]:
    try:
        return _load_base()
    except ArtifactIntegrityError as exc:
        st.error(
            "**A model file failed its integrity check, so nothing was loaded.** "
            "Restore the original files, or if you retrained on purpose run `make manifest`.\n\n"
            f"{exc}"
        )
    except (ArtifactNotFoundError, ManifestError) as exc:
        st.error(
            "**Model files are missing.** Run `make train-rf train-iforest manifest` "
            f"(after `make preprocess`) to create them.\n\n{exc}"
        )
    st.stop()


def get_detector() -> HybridDetector:
    base, _ = get_base()
    key = st.session_state.get("policy_key", "tiered")
    return base.with_policy(build_policy(key, base.threshold))


@st.cache_data
def load_features() -> list[str]:
    return json.loads((DATA_DIR / "features.json").read_text(encoding="utf-8"))


@st.cache_data
def load_eval() -> dict:
    path = REPORTS_DIR / "eval_results.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


@st.cache_resource(show_spinner="Preparing sample traffic…")
def load_pools() -> dict | None:
    test_path, withheld_path = DATA_DIR / "test.parquet", DATA_DIR / "withheld.parquet"
    if not test_path.exists():
        return None
    test = pd.read_parquet(test_path)
    pools = {
        "typical": test.sample(min(30_000, len(test)), random_state=7).reset_index(drop=True),
        "benign": test[test["is_attack"] == 0].sample(min(15_000, int((test["is_attack"] == 0).sum())),
                                                        random_state=7).reset_index(drop=True),
        "attacks": test[test["is_attack"] == 1].sample(min(15_000, int((test["is_attack"] == 1).sum())),
                                                         random_state=7).reset_index(drop=True),
        "novel": pd.read_parquet(withheld_path).reset_index(drop=True) if withheld_path.exists() else None,
    }
    return pools


@st.cache_resource(show_spinner="Preparing the explainer…")
def get_explainer():
    return make_explainer(get_base()[0].rf)


def draw_sample(pools: dict, mix: str, n: int, seed: int) -> pd.DataFrame:
    if mix == "attack_heavy":
        half = n // 2
        df = pd.concat([pools["attacks"].sample(half, random_state=seed),
                        pools["benign"].sample(n - half, random_state=seed)])
        df = df.sample(frac=1, random_state=seed)
    elif mix == "novel":
        df = pools["novel"].sample(min(n, len(pools["novel"])), random_state=seed)
    else:
        df = pools["typical"].sample(n, random_state=seed)
    return df.reset_index(drop=True)


# =============================================================================
# Scan state: models run once, the active policy is re-applied on demand
# =============================================================================
def run_scan(df: pd.DataFrame, source: str, fill_missing: bool) -> None:
    detector, _ = get_base()
    feats = load_features()
    clean = InputValidator(feats, max_rows=MAX_UPLOAD_ROWS, fill_missing=fill_missing).validate_df(df)
    signals = detector.signals(detector.scaler.transform(clean.to_numpy(dtype=np.float32)))
    meta = df.reset_index(drop=True).drop(columns=[c for c in feats if c in df.columns], errors="ignore")
    frame = pd.concat([meta, clean.reset_index(drop=True)], axis=1)
    for col in ("Label",):
        if col in frame:
            frame[col] = frame[col].astype(str).str.strip().map(pretty_label)
    st.session_state["scan"] = {
        "frame": frame,
        "signals": signals,
        "source": source,
        "time": datetime.now().strftime("%H:%M:%S"),
    }
    st.session_state.pop("inv_idx", None)


def current_results() -> pd.DataFrame | None:
    scan = st.session_state.get("scan")
    if not scan:
        return None
    detector = get_detector()
    sig = scan["signals"]
    labels, severities = detector.apply_policy(sig)
    res = scan["frame"].copy()
    res["rf_code"] = sig["rf_codes"]
    res["rf_label"] = [pretty_label(x) for x in sig["rf_labels"]]
    res["rf_confidence"] = sig["rf_confs"]
    res["anomaly_score"] = sig["if_scores"]
    res["final_label"] = [pretty_label(x) for x in labels]
    res["severity"] = severities
    return res


def truth_attack(res: pd.DataFrame) -> pd.Series | None:
    if "is_attack" in res.columns:
        return res["is_attack"].astype(int) == 1
    if "Label" in res.columns:
        return res["Label"].astype(str).str.strip().str.upper() != "BENIGN"
    return None


def policy_bands(key: str, base_thr: float) -> list[tuple[float, str]]:
    if key == "tiered":
        return [(DEEP_ANOMALY_THRESHOLD, "MEDIUM"), (base_thr, "LOW")]
    if key == "balanced":
        return [(0.0, "MEDIUM")]
    return [(base_thr, "MEDIUM")]


def need_scan(title: str) -> pd.DataFrame:
    res = current_results()
    if res is None:
        st.title(title)
        ui.situation("Nothing to show yet. Scan a batch of flows first.")
        st.page_link(PAGES["scan"], label="Go to Scan flows", icon=":material/radar:")
        st.stop()
    return res


def severity_counts(res: pd.DataFrame) -> dict[str, int]:
    vc = res["severity"].value_counts()
    return {s: int(vc.get(s, 0)) for s in ui.SEV_ORDER}


# =============================================================================
# Page: Overview
# =============================================================================
def page_overview() -> None:
    detector, info = get_base()
    ev = load_eval()
    key = st.session_state.get("policy_key", "tiered")
    pc = ev.get("policy_comparison", {})

    st.title("Network intrusion detection")
    scan = st.session_state.get("scan")
    last = (f"Last scan: {len(scan['frame']):,} flows at {ui.esc(scan['time'])}."
            if scan else "No traffic scanned yet. Open <b>Scan flows</b> to inspect a batch.")
    ui.situation(
        f"All <b>{len(info)}</b> model files passed their SHA-256 check. "
        f"Alerts follow the <b>{ui.esc(POLICY_INFO[key]['short'])}</b> policy. {last}"
    )

    if not pc:
        st.warning("No evaluation results found. Run `make evaluate` to generate `reports/eval_results.json`.")
        return

    active = pc[key]
    infil_key = next((k for k in active["withheld"]["per_label"] if k.startswith("Infiltration")), None)

    # -- Hero: the trade-off every SOC has to choose ------------------------------------------------
    st.subheader("What each policy costs")
    ui.note("Moving left means fewer false alarms. Moving up means more of the unseen Infiltration flows are "
            "flagged for an analyst. The test data holds only 36 Infiltration flows, so read the vertical "
            "position as indicative rather than a guarantee.")
    rows = []
    for k, p in pc.items():
        rows.append({
            "Policy": p["short"],
            "False alarms (%)": p["actionable"]["fpr"] * 100,
            "Infiltration flagged (%)": (p["withheld"]["per_label"][infil_key]["actionable"] * 100) if infil_key else 0,
            "Precision (%)": p["actionable"]["precision"] * 100,
            "Alerts paging an analyst": p["actionable"]["n_alerts"],
            "Selected": "Active" if k == key else "Other",
        })
    df = pd.DataFrame(rows)
    base = alt.Chart(df).encode(
        x=alt.X("False alarms (%):Q", scale=alt.Scale(domain=[0, max(12.0, df["False alarms (%)"].max() * 1.3)])),
        y=alt.Y("Infiltration flagged (%):Q", scale=alt.Scale(domain=[0, 100])),
    )
    points = base.mark_circle(size=320, opacity=1).encode(
        color=alt.Color("Selected:N", legend=None,
                        scale=alt.Scale(domain=["Active", "Other"], range=[ui.BRAND, "#5C6F8F"])),
        tooltip=["Policy", alt.Tooltip("False alarms (%):Q", format=".1f"),
                 alt.Tooltip("Infiltration flagged (%):Q", format=".1f"),
                 alt.Tooltip("Precision (%):Q", format=".1f"), "Alerts paging an analyst"],
    )
    labels = base.mark_text(align="left", dx=14, fontSize=13, color=ui.TEXT).encode(text="Policy:N")
    st.altair_chart(ui.style(points + labels, height=320), width="stretch")

    # -- Active-policy numbers ----------------------------------------------------------------------
    st.subheader(f"{POLICY_INFO[key]['short']} policy on the held-out test set")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        ui.metric("Known attacks caught", f"{active['actionable']['recall']:.2%}", "good",
                  help="Share of attack flows that raised a High or Medium alert.")
    with c2:
        ui.metric("False alarms", f"{active['actionable']['fpr']:.2%}", "medium",
                  help="Share of benign flows that raised a High or Medium alert.")
    with c3:
        ui.metric("Alert precision", f"{active['actionable']['precision']:.1%}", "plain",
                  help="Of the High and Medium alerts, how many were real attacks.")
    with c4:
        ui.metric("Novel threats flagged", f"{active['withheld']['overall_actionable']:.1%}", "high",
                  help="Share of the 2,179 withheld attack flows (Infiltration and Web attacks) flagged.")
    if active["all_alerts"]["n_alerts"] != active["actionable"]["n_alerts"]:
        extra = active["all_alerts"]["n_alerts"] - active["actionable"]["n_alerts"]
        ui.note(f"The policy also files {extra:,} Low-severity flows to a hunting queue; they are excluded above "
                "because they do not page anyone.")

    # -- Novel threats ------------------------------------------------------------------------------
    st.subheader("Attacks the classifier was never trained on")
    w = ev["withheld_experiment"]["per_label"]
    rows = []
    for lbl, s in w.items():
        total = max(s["total"], 1)
        act = active["withheld"]["per_label"].get(lbl, {}).get("actionable", 0)
        name = pretty_label(lbl)
        rows += [
            {"Attack": name, "Detector": "Classifier alone", "Flagged (%)": s["rf_detected"] / total * 100, "Flows": s["total"]},
            {"Attack": name, "Detector": "Anomaly detector alone", "Flagged (%)": s["if_detected"] / total * 100, "Flows": s["total"]},
            {"Attack": name, "Detector": "Combined, active policy", "Flagged (%)": act * 100, "Flows": s["total"]},
        ]
    nd = pd.DataFrame(rows)
    chart = alt.Chart(nd).mark_bar().encode(
        y=alt.Y("Attack:N", sort="-x", title=None),
        x=alt.X("Flagged (%):Q", scale=alt.Scale(domain=[0, 100])),
        yOffset="Detector:N",
        color=alt.Color("Detector:N", scale=alt.Scale(
            domain=["Classifier alone", "Anomaly detector alone", "Combined, active policy"],
            range=["#5C6F8F", "#6E9BD1", ui.BRAND])),
        tooltip=["Attack", "Detector", alt.Tooltip("Flagged (%):Q", format=".1f"), "Flows"],
    )
    st.altair_chart(ui.style(chart, height=260), width="stretch")
    ui.note("The anomaly detector is what rescues Infiltration. The three Web attack types look like ordinary web "
            "browsing at the flow level, so both detectors mostly miss them; they need payload inspection (a WAF).")

    with st.expander("Evaluated data and limits"):
        st.dataframe(pd.DataFrame({
            "Capture file": ["Monday", "Tuesday", "Wednesday", "Thursday morning", "Thursday afternoon",
                             "Friday morning", "Friday afternoon (PortScan)", "Friday afternoon (DDoS)"],
            "Raw flows": [529_918, 445_909, 692_703, 170_366, 288_602, 191_033, 286_467, 225_745],
            "Contents": ["Normal traffic", "FTP-Patator, SSH-Patator",
                         "DoS Hulk, GoldenEye, slowloris, Slowhttptest, Heartbleed",
                         "Web attacks (withheld from training)", "Infiltration (withheld from training)",
                         "Botnet", "PortScan", "DDoS"],
        }), hide_index=True, width="stretch")
        st.markdown(
            "- This console scores **flow records** (CSV from CICFlowMeter, Zeek or NetFlow). It does not capture packets.\n"
            "- Features are timing and size statistics, so encrypted or application-layer attacks can look normal.\n"
            "- Models were trained on 2017 traffic. Retrain on your own network before relying on the thresholds."
        )


# =============================================================================
# Page: Scan flows
# =============================================================================
def page_scan() -> None:
    feats = load_features()
    st.title("Scan flows")
    ui.situation("Pick some traffic, run it through the classifier and the anomaly detector, "
                 "then work through what they flag.")

    pools = load_pools()
    options = ["Sample traffic", "Upload CSV"] if pools else ["Upload CSV"]
    source = st.segmented_control("Traffic source", options, default=options[0], key="scan_source") or options[0]

    df_in: pd.DataFrame | None = None
    fill_missing = False
    source_label = ""

    if source == "Sample traffic":
        mix = st.selectbox("Mix", list(MIX_LABELS), format_func=MIX_LABELS.get, key="scan_mix",
                           disabled=False)
        cap = 2179 if mix == "novel" and pools.get("novel") is not None else 5000
        if mix == "novel" and pools.get("novel") is None:
            st.error("`data/processed/withheld.parquet` is missing. Run `make preprocess`.")
            st.stop()
        n = st.slider("Flows", 100, cap, min(1000, cap), step=100 if cap >= 1000 else 50, key="scan_n")
        source_label = f"Sample, {MIX_LABELS[mix].split(' (')[0].lower()}"
        ui.note("Samples come from the held-out test split, which no model was trained on.")
    else:
        ui.note(f"Up to {MAX_UPLOAD_ROWS:,} rows and {MAX_UPLOAD_MB} MB. The file needs the {len(feats)} CIC-IDS2017 "
                "feature columns. Label, Timestamp and IP columns are optional and used when present.")
        up = st.file_uploader("Flow CSV", type=["csv"], key="scan_upload")
        st.download_button("Download an empty template", ",".join(feats) + "\n", file_name="flow_template.csv",
                           mime="text/csv", icon=":material/download:")
        fill_missing = st.checkbox("Treat missing feature columns as 0 (testing only)", value=False, key="scan_fill",
                                   help="Scores will be unreliable. Use only to try the console on partial data.")
        if up is None:
            st.stop()
        if up.size > MAX_UPLOAD_BYTES:
            st.error(f"The file is {up.size / 1e6:.1f} MB; the limit is {MAX_UPLOAD_MB} MB. Split it and upload in parts.")
            st.stop()
        try:
            df_in = pd.read_csv(io.BytesIO(up.getvalue()), nrows=MAX_UPLOAD_ROWS + 1, low_memory=False,
                                encoding="utf-8", encoding_errors="replace")
        except (pd.errors.EmptyDataError, pd.errors.ParserError) as exc:
            st.error(f"This file could not be read as CSV. {exc}")
            st.stop()
        df_in.columns = df_in.columns.astype(str).str.strip()
        if len(df_in) > MAX_UPLOAD_ROWS:
            st.error(f"The file has more than {MAX_UPLOAD_ROWS:,} rows. Split it into smaller files.")
            st.stop()
        missing = [f for f in feats if f not in df_in.columns]
        if missing and not fill_missing:
            st.error(f"{len(missing)} required columns are missing, for example: {', '.join(missing[:6])}. "
                     "Use the template for the exact header.")
            st.stop()
        st.success(f"{len(df_in):,} rows and {len(df_in.columns)} columns look ready to scan.")
        source_label = f"Upload, {up.name}"

    if st.button("Scan flows", type="primary", icon=":material/radar:"):
        try:
            if source == "Sample traffic":
                seed = st.session_state.get("scan_draw", 0) + 1
                st.session_state["scan_draw"] = seed
                df_in = draw_sample(pools, mix, n, seed)
            with st.spinner("Scoring flows…"):
                run_scan(df_in, source_label, fill_missing)
        except ValidationError as exc:
            st.error(f"The data was rejected: {exc}")
            st.stop()

    res = current_results()
    if res is None:
        return
    st.divider()
    render_scan_results(res)


def render_scan_results(res: pd.DataFrame) -> None:
    scan = st.session_state["scan"]
    counts = severity_counts(res)
    attention = counts["HIGH"] + counts["MEDIUM"] + counts["LOW"]
    ui.situation(
        f"<b>{len(res):,}</b> flows scanned ({ui.esc(scan['source'])}, {ui.esc(scan['time'])}). "
        f"<b>{counts['HIGH']:,}</b> are known attacks, <b>{counts['MEDIUM'] + counts['LOW']:,}</b> look unusual, "
        f"and <b>{counts['INFO']:,}</b> look normal."
        + ("" if attention else " Nothing needs attention.")
    )
    ui.severity_bar(counts)

    truth = truth_attack(res)
    tabs = st.tabs(["Flows", "Threat types"] + (["Ground truth check"] if truth is not None else []))

    with tabs[0]:
        fc1, fc2 = st.columns([2, 1])
        with fc1:
            sev_sel = st.multiselect("Severity", ui.SEV_ORDER, default=[s for s in ui.SEV_ORDER if s != "INFO"],
                                     format_func=lambda s: ui.SEVERITY[s]["label"], key="flows_sev")
        with fc2:
            text = st.text_input("Search threat type", key="flows_text", placeholder="for example DoS")
        view = res[res["severity"].isin(sev_sel)]
        if text:
            view = view[view["final_label"].str.contains(text, case=False, regex=False)]
        view = view.sort_values(["anomaly_score"]).sort_values("severity", key=lambda s: s.map(ui.SEV_RANK), kind="stable")
        show = pd.DataFrame({
            "Flow": view.index,
            **({"True label": view["Label"].values} if "Label" in view else {}),
            "Verdict": view["final_label"].values,
            "Severity": view["severity"].map(lambda s: ui.SEVERITY[s]["label"]).values,
            "Classifier says": view["rf_label"].values,
            "Classifier confidence": view["rf_confidence"].values,
            "Anomaly score": view["anomaly_score"].values,
        })
        for extra in ("Timestamp", *SRC_IP_ALIASES[:2], *DST_IP_ALIASES[:2]):
            if extra in view.columns and extra not in show.columns:
                show[extra] = view[extra].values
        if show.empty:
            st.info("No flows match these filters. Widen the severity selection or clear the search.")
        else:
            st.dataframe(
                show.head(MAX_TABLE_ROWS), hide_index=True, width="stretch", height=420,
                column_config={
                    "Classifier confidence": st.column_config.ProgressColumn(min_value=0, max_value=1, format="percent"),
                    "Anomaly score": st.column_config.NumberColumn(format="%.4f",
                                                                   help="Lower is more unusual."),
                },
            )
            if len(show) > MAX_TABLE_ROWS:
                ui.note(f"Showing the first {MAX_TABLE_ROWS:,} of {len(show):,} flows. Download the CSV for all of them.")
            st.download_button("Download these flows as CSV", show.to_csv(index=False), file_name="flows.csv",
                               mime="text/csv", icon=":material/download:")

    with tabs[1]:
        alerts = res[res["severity"] != "INFO"]
        if alerts.empty:
            st.info("No alerts in this batch, so there are no threat types to chart.")
        else:
            agg = (alerts.groupby(["final_label", "severity"]).size().reset_index(name="Flows"))
            agg["Severity"] = agg["severity"].map(lambda s: ui.SEVERITY[s]["label"])
            chart = alt.Chart(agg).mark_bar().encode(
                y=alt.Y("final_label:N", sort="-x", title=None),
                x=alt.X("Flows:Q"),
                color=alt.Color("Severity:N", scale=ui.sev_scale(["HIGH", "MEDIUM", "LOW"]), legend=alt.Legend(title=None)),
                tooltip=["final_label", "Severity", "Flows"],
            )
            st.altair_chart(ui.style(chart, height=max(120, 34 * agg["final_label"].nunique())), width="stretch")
            ui.note(f"{counts['INFO']:,} normal flows are left out of this chart.")

    if truth is not None:
        with tabs[2]:
            flagged = res["severity"] != "INFO"
            paged = res["severity"].isin(["HIGH", "MEDIUM"])
            n_att, n_ben = int(truth.sum()), int((~truth).sum())
            g1, g2, g3, g4 = st.columns(4)
            with g1:
                ui.metric("Attacks in batch", f"{n_att:,}", "plain")
            with g2:
                ui.metric("Attacks flagged", f"{(flagged & truth).sum() / max(n_att, 1):.1%}", "good",
                          help="Any severity, including Low.")
            with g3:
                ui.metric("Attacks paged", f"{(paged & truth).sum() / max(n_att, 1):.1%}", "good",
                          help="High or Medium only, the alerts that page an analyst.")
            with g4:
                ui.metric("False alarms", f"{(paged & ~truth).sum() / max(n_ben, 1):.2%}", "medium",
                          help="Benign flows that raised a High or Medium alert.")
            if "Label" in res.columns:
                t = res[truth].assign(_flag=flagged[truth], _page=paged[truth])
                by = (t.groupby("Label").agg(Flows=("Label", "size"), Flagged=("_flag", "sum"), Paged=("_page", "sum"))
                      .reset_index().sort_values("Flows", ascending=False))
                by["Flagged (%)"] = by["Flagged"] / by["Flows"] * 100
                by["Paged (%)"] = by["Paged"] / by["Flows"] * 100
                st.dataframe(by.rename(columns={"Label": "True attack type"}), hide_index=True, width="stretch",
                             column_config={
                                 "Flagged (%)": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f%%"),
                                 "Paged (%)": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f%%"),
                             })


# =============================================================================
# Page: Incidents
# =============================================================================
def _ip_col(df: pd.DataFrame, aliases: tuple[str, ...]) -> str | None:
    return next((c for c in aliases if c in df.columns), None)


def incident_members(alerts: pd.DataFrame, inc: pd.Series, mode: str) -> pd.DataFrame:
    m = (alerts["final_label"] == inc["label"]) & (alerts["severity"] == inc["severity"])
    for col, field in ((_ip_col(alerts, SRC_IP_ALIASES), "src_ip"), (_ip_col(alerts, DST_IP_ALIASES), "dst_ip")):
        if col and field in inc and pd.notna(inc[field]):
            m &= alerts[col].astype(str) == str(inc[field])
    if mode == "time":
        ts = pd.to_datetime(alerts["Timestamp"], errors="coerce")
        m &= (ts >= inc["window_start"]) & (ts < inc["window_end"])
    else:
        m &= (alerts.index >= inc["window_start"]) & (alerts.index <= inc["window_end"])
    return alerts[m]


def page_incidents() -> None:
    res = need_scan("Incidents")
    st.title("Incidents")

    has_ts = "Timestamp" in res.columns and pd.to_datetime(res["Timestamp"], errors="coerce").notna().any()
    modes = (["time"] if has_ts else []) + ["batch", "order"]
    mode_names = {"time": "Time windows of 60 seconds", "batch": "Threat type across the whole batch",
                  "order": "Capture order (flows near each other)"}

    c1, c2, c3 = st.columns([2, 2, 1])
    with c1:
        sev_sel = st.multiselect("Severity", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"],
                                 format_func=lambda s: ui.SEVERITY[s]["label"], key="inc_sev")
    with c2:
        mode = st.selectbox("Group flows by", modes, format_func=mode_names.get, key="inc_mode")
    with c3:
        min_flows = st.slider("Minimum flows", 2, 20, 5, key="inc_min")

    alerts = res[res["severity"].isin(sev_sel)]
    if mode != "time":
        alerts = alerts.drop(columns=["Timestamp"], errors="ignore")
    grouper = AlertGrouper(
        min_alerts=min_flows,
        max_index_gap=len(res) + 1 if mode == "batch" else 50,
        max_group_size=len(alerts) + 1 if mode == "batch" else 1000,
        include_benign=False,
    )
    groups = grouper.group(alerts) if len(alerts) else []
    kpi = summarize_groups(groups, len(alerts))

    ui.situation(
        f"<b>{kpi['raw_alerts']:,}</b> alerts collapse into <b>{kpi['incidents']:,}</b> incidents"
        + (f" and <b>{kpi['ungrouped_alerts']:,}</b> single alerts, an analyst queue of <b>{kpi['analyst_queue']:,}</b>."
           if kpi["raw_alerts"] else ".")
    )
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        ui.metric("Alerts", f"{kpi['raw_alerts']:,}", "plain")
    with k2:
        ui.metric("Incidents", f"{kpi['incidents']:,}", "high")
    with k3:
        ui.metric("Single alerts", f"{kpi['ungrouped_alerts']:,}", "medium",
                  help=f"Alerts in groups smaller than {min_flows} flows stay as individual alerts.")
    with k4:
        ui.metric("Queue reduction", f"{kpi['queue_reduction']:.0%}", "good",
                  help="1 − (incidents + single alerts) ÷ alerts.")
    if mode == "batch":
        ui.note("Samples are drawn in random order, so grouping by capture order would be meaningless. Upload a CSV "
                "with Timestamp (and IP) columns to group by time and host.")
    elif _ip_col(alerts, SRC_IP_ALIASES):
        ui.note("Incidents are also split by source and destination IP.")

    gdf = groups_to_dataframe(groups)
    if gdf.empty:
        st.info("No incidents formed. Lower the minimum flows, or include more severities.")
        return
    gdf["_rank"] = gdf["severity"].map(ui.SEV_RANK)
    gdf = gdf.sort_values(["_rank", "count"], ascending=[True, False]).drop(columns="_rank").reset_index(drop=True)
    shown = gdf.assign(severity=gdf["severity"].map(lambda s: ui.SEVERITY[s]["label"])).rename(columns={
        "group_id": "Incident", "label": "Threat", "severity": "Severity", "count": "Flows",
        "avg_confidence": "Mean confidence", "avg_anomaly_score": "Mean anomaly score",
        "window_start": "From", "window_end": "To", "src_ip": "Source", "dst_ip": "Destination",
    })
    if mode == "batch":  # first/last index of a randomly ordered batch carries no meaning
        shown = shown.drop(columns=["From", "To"])
    event = st.dataframe(
        shown, hide_index=True, width="stretch", height=min(380, 40 + 35 * len(shown)), on_select="rerun", selection_mode="single-row",
        key="inc_table",
        column_config={"Mean confidence": st.column_config.ProgressColumn(min_value=0, max_value=1, format="percent")},
    )
    ui.note("Select a row to see its flows.")
    sel = event.selection.rows if event and event.selection else []
    if not sel:
        return

    inc = gdf.iloc[sel[0]]
    members = incident_members(alerts, inc, mode)
    st.subheader(f"{inc['label']} · {len(members):,} flows")
    order = members.sort_values("anomaly_score")
    pick = st.selectbox(
        "Open a flow in Investigate", order.index[:300].tolist(),
        format_func=lambda i: f"Flow {i}, anomaly score {order.loc[i, 'anomaly_score']:+.3f}",
        key=f"inc_pick_{inc['group_id']}",
    )
    if st.button("Investigate this flow", icon=":material/search_insights:"):
        st.session_state["inv_idx"] = int(pick)
        st.switch_page(PAGES["investigate"])
    st.dataframe(
        order[["rf_label", "rf_confidence", "anomaly_score"]].rename(columns={
            "rf_label": "Classifier says", "rf_confidence": "Classifier confidence", "anomaly_score": "Anomaly score"})
        .head(MAX_TABLE_ROWS),
        width="stretch", height=260,
        column_config={"Classifier confidence": st.column_config.ProgressColumn(min_value=0, max_value=1, format="percent")},
    )


# =============================================================================
# Page: Investigate flow
# =============================================================================
def page_investigate() -> None:
    res = need_scan("Investigate flow")
    st.title("Investigate flow")

    feats = load_features()
    detector = get_detector()
    key = st.session_state.get("policy_key", "tiered")
    alerts = res[res["severity"] != "INFO"]
    if alerts.empty:
        ui.situation("This batch has no alerts to investigate. Every flow looks normal under the active policy.")
        return

    ranked = alerts.assign(_r=alerts["severity"].map(ui.SEV_RANK)).sort_values(["_r", "anomaly_score"])
    options = ranked.index[:500].tolist()
    jump = st.session_state.pop("inv_idx", None)
    if jump is not None and jump in res.index:
        if jump not in options:
            options.insert(0, jump)
        st.session_state["inv_select"] = jump
    if st.session_state.get("inv_select") not in options:
        st.session_state["inv_select"] = options[0]

    idx = st.selectbox(
        "Flow", options, key="inv_select",
        format_func=lambda i: f"Flow {i}: {res.loc[i, 'final_label']} ({ui.SEVERITY[res.loc[i, 'severity']]['label']})",
    )
    row = res.loc[idx]
    sev = row["severity"]
    conf, score = float(row["rf_confidence"]), float(row["anomaly_score"])

    if sev == "HIGH":
        story = (f"The classifier is <b>{conf:.0%}</b> sure this flow is <b>{ui.esc(row['rf_label'])}</b>. "
                 f"The anomaly detector scores it {score:+.3f}, "
                 + ("which also marks it as unusual." if score < detector.threshold else "which looks ordinary on its own."))
    else:
        story = (f"The classifier calls this flow benign ({conf:.0%} sure), but the anomaly detector scores it "
                 f"<b>{score:+.3f}</b>, outside what normal traffic looks like. Treat it as a lead, not a verdict.")
    ui.situation(story)

    left, right = st.columns([1, 2])
    with left:
        st.markdown(f"**Severity** &nbsp;{ui.sev_chip(sev)}", unsafe_allow_html=True)
        st.markdown(f"**Verdict** &nbsp;{ui.esc(row['final_label'])}")
        st.markdown(f"**Classifier** &nbsp;{ui.esc(row['rf_label'])}")
        if "Label" in res.columns:
            st.markdown(f"**True label** &nbsp;{ui.esc(row['Label'])}")
        for c in (*SRC_IP_ALIASES[:2], *DST_IP_ALIASES[:2], "Timestamp"):
            if c in res.columns:
                st.markdown(f"**{ui.esc(c)}** &nbsp;{ui.esc(row[c])}")
    with right:
        ui.score_ruler(score, policy_bands(key, detector.threshold))

    default_view = "Why the classifier decided" if sev == "HIGH" else "How unusual the flow is"
    view = st.segmented_control(
        "Evidence", ["Why the classifier decided", "How unusual the flow is", "All feature values"],
        default=default_view, key=f"inv_view_{idx}_{sev}", label_visibility="collapsed",
    ) or default_view

    x_raw = row[feats].to_numpy(dtype=np.float64)

    if view == "Why the classifier decided":
        known = {detector.label_map[int(c)]: int(c) for c in detector.rf.classes_}
        names = [pretty_label(n) for n in known]
        raw_by_pretty = {pretty_label(n): c for n, c in known.items()}
        explain_name = st.selectbox("Explain class", names, index=names.index(row["rf_label"])
                                    if row["rf_label"] in names else 0, key=f"inv_cls_{idx}",
                                    help="Defaults to the class the forest chose. Pick another to ask 'why not this one?'")
        with st.spinner("Computing Shapley values…"):
            att = shap_attribution(get_explainer(), detector.rf, detector.scaler.transform(x_raw.reshape(1, -1)),
                                   feats, raw_by_pretty[explain_name], top_k=15)
        chart = alt.Chart(att).mark_bar().encode(
            y=alt.Y("feature:N", sort=alt.EncodingSortField("shap", op="max", order="descending"), title=None),
            x=alt.X("shap:Q", title=f"Push toward or away from {explain_name}"),
            color=alt.Color("direction:N", legend=alt.Legend(title=None),
                            scale=alt.Scale(domain=["toward class", "away from class"], range=["#F08A3C", "#6E9BD1"])),
            tooltip=["feature", alt.Tooltip("shap:Q", format="+.4f"), "direction"],
        )
        st.altair_chart(ui.style(chart, height=420), width="stretch")
        if sev != "HIGH":
            ui.note("This flow was raised by the anomaly detector, not the classifier. The chart explains the "
                    "classifier's view; the next tab shows what made the flow look unusual.")
    else:
        dev = baseline_deviation(detector.scaler, x_raw, feats, top_k=15 if view != "All feature values" else len(feats))
        if view == "How unusual the flow is":
            chart = alt.Chart(dev).mark_bar().encode(
                y=alt.Y("feature:N", sort=alt.EncodingSortField("z_score", op="max", order="descending"), title=None),
                x=alt.X("z_score:Q", title="Standard deviations from the training average"),
                color=alt.condition(alt.datum.z_score > 0, alt.value("#F08A3C"), alt.value("#6E9BD1")),
                tooltip=["feature", alt.Tooltip("value:Q", format=",.2f"), alt.Tooltip("baseline_mean:Q", format=",.2f"),
                         alt.Tooltip("z_score:Q", format="+.2f")],
            )
            st.altair_chart(ui.style(chart, height=420), width="stretch")
            ui.note("Bars show how far each feature sits from the average training flow. Large values in either "
                    "direction are what an anomaly detector reacts to, though it weighs combinations, not single features.")
        else:
            st.dataframe(dev.rename(columns={"feature": "Feature", "value": "Value", "baseline_mean": "Training average",
                                             "z_score": "Standard deviations"}),
                         hide_index=True, width="stretch", height=460)


# =============================================================================
# Page: Detector health
# =============================================================================
def page_health() -> None:
    st.title("Detector health")
    detector, info = get_base()
    key = st.session_state.get("policy_key", "tiered")
    ui.situation(f"Model files verified against <code>models/manifest.json</code>. The anomaly detector flags flows "
                 f"scoring below <b>{detector.threshold:+.4f}</b> under the baseline policy.")
    st.dataframe(pd.DataFrame(info), hide_index=True, width="stretch")
    ui.note("The manifest sits next to the models, so it detects corruption and casual tampering. For production, "
            "keep it on read-only storage or sign it.")


    st.subheader("Input drift")
    ref = drift_mod.load_reference(DRIFT_REFERENCE_PATH)
    cur = current_results()
    if ref is None:
        ui.note("No drift reference found. Run <code>make drift-reference</code> to create one.")
    elif cur is None:
        st.caption("Run a scan to compare its traffic with the validation baseline.")
    else:
        rep = drift_mod.assess(ref, cur, cur["anomaly_score"].to_numpy() if "anomaly_score" in cur else None)
        if rep["status"] == "insufficient_data":
            st.caption("Scan has too few flows for a reliable drift reading (needs 200+).")
        else:
            st.metric("Median feature PSI", f"{rep['median_psi']:.3f}", rep["status"])
            st.caption("PSI below 0.10 is stable, 0.10 to 0.25 moderate, above 0.25 significant. Significant drift "
                       "means thresholds need recalibrating on this traffic.")
            st.dataframe(pd.DataFrame(rep["top_drifted"]), hide_index=True, width="stretch")

    st.subheader("What the classifier knows")
    known = {pretty_label(detector.label_map[int(c)]) for c in detector.rf.classes_}
    unseen = sorted(pretty_label(v) for v in detector.label_map.values() if pretty_label(v) not in known)
    k1, k2 = st.columns(2)
    with k1:
        st.markdown("**Trained on**")
        st.write(", ".join(sorted(known)))
    with k2:
        st.markdown("**Never seen** (only the anomaly detector can catch these)")
        st.write(", ".join(unseen) if unseen else "None")

    res = current_results()
    st.subheader("Anomaly scores in the current scan")
    if res is None:
        st.info("Scan a batch to see how its anomaly scores are distributed.")
        st.page_link(PAGES["scan"], label="Go to Scan flows", icon=":material/radar:")
    else:
        d = res[["anomaly_score", "severity"]].copy()
        d["Severity"] = d["severity"].map(lambda s: ui.SEVERITY[s]["label"])
        bands = policy_bands(key, detector.threshold)
        hist = alt.Chart(d).mark_bar(opacity=0.9).encode(
            x=alt.X("anomaly_score:Q", bin=alt.Bin(maxbins=60), title="Anomaly score (lower is more unusual)"),
            y=alt.Y("count():Q", title="Flows"),
            color=alt.Color("Severity:N", scale=ui.sev_scale(), legend=alt.Legend(title=None)),
        )
        rules = alt.Chart(pd.DataFrame({"x": [b for b, _ in bands]})).mark_rule(
            color=ui.TEXT, strokeDash=[5, 4]).encode(x="x:Q")
        st.altair_chart(ui.style(hist + rules, height=300), width="stretch")
        ui.note("Dashed lines are the active policy's thresholds.")

        truth = truth_attack(res)
        st.subheader("Threshold sensitivity")
        if truth is None:
            st.info("This scan has no ground-truth labels, so false-alarm and recall curves are unavailable. "
                    "Scan sample traffic or a CSV with a Label column.")
        else:
            sig = st.session_state["scan"]["signals"]
            rf_attack = sig["rf_codes"] != detector._benign_code
            ts = np.round(np.linspace(-0.15, 0.15, 61), 4)
            y = truth.to_numpy()
            rows = []
            for t in ts:
                a = rf_attack | (sig["if_scores"] < t)
                rows.append({"Threshold": t,
                             "Attacks caught (%)": (a & y).sum() / max(y.sum(), 1) * 100,
                             "False alarms (%)": (a & ~y).sum() / max((~y).sum(), 1) * 100})
            curve = pd.DataFrame(rows).melt("Threshold", var_name="Measure", value_name="Percent")
            t_pick = st.slider("Try a threshold", -0.15, 0.15, float(np.clip(detector.threshold, -0.15, 0.15)), 0.005)
            line = alt.Chart(curve).mark_line(strokeWidth=2.5).encode(
                x=alt.X("Threshold:Q", title="Anomaly threshold"), y=alt.Y("Percent:Q", scale=alt.Scale(domain=[0, 100])),
                color=alt.Color("Measure:N", scale=alt.Scale(domain=["Attacks caught (%)", "False alarms (%)"],
                                                              range=[ui.BRAND, "#F08A3C"]), legend=alt.Legend(title=None)),
            )
            rule = alt.Chart(pd.DataFrame({"x": [t_pick]})).mark_rule(color=ui.TEXT, strokeDash=[5, 4]).encode(x="x:Q")
            st.altair_chart(ui.style(line + rule, height=300), width="stretch")
            a = rf_attack | (sig["if_scores"] < t_pick)
            m1, m2, m3 = st.columns(3)
            with m1:
                ui.metric("Attacks caught", f"{(a & y).sum() / max(y.sum(), 1):.1%}", "good")
            with m2:
                ui.metric("False alarms", f"{(a & ~y).sum() / max((~y).sum(), 1):.2%}", "medium")
            with m3:
                ui.metric("Alerts raised", f"{int(a.sum()):,}", "plain")
            ui.note("This curve uses the current batch only. Use a large, representative batch before changing "
                    "a production threshold.")

    with st.expander("Operating limits"):
        st.dataframe(pd.DataFrame({
            "Setting": ["Maximum rows per upload", "Maximum upload size", "Integrity check at start-up",
                        "Baseline anomaly threshold", "Deep anomaly threshold (tiered)"],
            "Value": [f"{MAX_UPLOAD_ROWS:,}", f"{MAX_UPLOAD_MB} MB", "On, before any model is deserialised",
                      f"{detector.threshold:+.6f}", f"{DEEP_ANOMALY_THRESHOLD:+.2f}"],
        }), hide_index=True, width="stretch")



# =============================================================================
# Alert history (incident database)
# =============================================================================
@st.cache_resource(show_spinner=False)
def get_store() -> IncidentStore:
    return IncidentStore(DB_PATH)


def page_history() -> None:
    st.title("Alert history")
    store = get_store()
    stats = store.stats()
    total = sum(stats["by_severity"].values())
    ui.situation(f"<b>{total:,}</b> alerts stored from <b>{stats['batches']:,}</b> scans "
                 f"({stats['flows_scanned']:,} flows). Written by the API and the folder ingestor.")
    if not total:
        ui.note("No alerts stored yet. Score flows through the API or the folder ingestor and they appear here.")
        return
    f1, f2 = st.columns(2)
    sev = f1.multiselect("Severity", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM"])
    status = f2.selectbox("Status", ["any", *STATUSES])
    rows = store.list_alerts(sev or None, None if status == "any" else status, 500, 0)
    if not rows:
        st.info("No alerts match these filters. Widen the severity or status filter.")
        return
    df = pd.DataFrame(rows)
    shown = [c for c in ("created_at", "severity", "final_label", "src_ip", "dst_ip", "rf_confidence",
                         "anomaly_score", "status", "alert_id") if c in df.columns]
    df["created_at"] = pd.to_datetime(df["created_at"], unit="s").dt.strftime("%Y-%m-%d %H:%M:%S")
    event = st.dataframe(df[shown], hide_index=True, width="stretch", on_select="rerun",
                         selection_mode="single-row")
    if not event.selection.rows:
        st.caption("Select a row to record a verdict.")
        return
    row = df.iloc[event.selection.rows[0]]
    st.subheader(f"{row['final_label']} from {row.get('src_ip') or 'unknown source'}")
    note_text = st.text_input("Note (optional)", max_chars=500, key="verdict_note")
    c1, c2, c3 = st.columns(3)
    for col, (verdict, label) in zip((c1, c2, c3), (("acknowledged", "Acknowledge"), ("confirmed", "Confirm attack"),
                                                    ("false_positive", "Mark false positive"))):
        if col.button(label, width="stretch", key=f"v_{verdict}"):
            store.set_status(row["alert_id"], verdict, note_text)
            st.toast(f"Marked {verdict.replace('_', ' ')}")
            st.rerun()
    st.caption("Confirmed and false-positive verdicts feed the retraining export "
               "(`GET /v1/feedback/export`).")

# =============================================================================
# Navigation and sidebar
# =============================================================================
PAGES = {
    "overview": st.Page(page_overview, title="Overview", icon=":material/dashboard:", url_path="overview", default=True),
    "scan": st.Page(page_scan, title="Scan flows", icon=":material/radar:", url_path="scan"),
    "incidents": st.Page(page_incidents, title="Incidents", icon=":material/crisis_alert:", url_path="incidents"),
    "investigate": st.Page(page_investigate, title="Investigate flow", icon=":material/search_insights:",
                           url_path="investigate"),
    "history": st.Page(page_history, title="Alert history", icon=":material/history:", url_path="history"),
    "health": st.Page(page_health, title="Detector health", icon=":material/monitor_heart:", url_path="health"),
}

require_login()
nav = st.navigation(list(PAGES.values()), position="sidebar")

with st.sidebar:
    st.divider()
    st.selectbox(
        "Alert policy", list(POLICY_INFO), key="policy_key",
        format_func=lambda k: POLICY_INFO[k]["label"],
        help="Changes how model outputs become severities. Takes effect immediately on the current scan.",
    )
    st.caption(POLICY_INFO[st.session_state.get("policy_key", "tiered")]["summary"])
    _, _info = get_base()
    st.caption(f":material/verified_user: {len(_info)} model files verified")
    sidebar_status()

nav.run()
