#!/usr/bin/env python3
"""Generate verified architecture diagram and evaluation charts for the MCA S3 Interim Report."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT_DIR = Path("/home/anandhu/projects/interim_audit/submission/figures")
OUT_DIR.mkdir(parents=True, exist_ok=True)
EVAL_JSON = Path("/home/anandhu/projects/network-ids/reports/eval_results.json")


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]
    for p in candidates:
        if Path(p).exists():
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def build_architecture_diagram() -> Path:
    dot_src = r'''
digraph NIDS {
    rankdir=TB;
    compound=true;
    bgcolor="white";
    fontname="DejaVu Sans";
    node [shape=box, style="rounded,filled", fontname="DejaVu Sans", fontsize=11, margin="0.16,0.10", penwidth=1.3];
    edge [fontname="DejaVu Sans", fontsize=9.5, color="#334155", penwidth=1.2];

    subgraph cluster_offline {
        label="Offline Training & Calibration Pipeline";
        style="rounded,filled";
        fillcolor="#F8FAFC";
        color="#94A3B8";
        fontsize=12;
        fontname="DejaVu Sans";

        raw [label="CIC-IDS2017 Raw Corpus\n8 CSV Files | 2,830,743 Flows", fillcolor="#E2E8F0", color="#475569"];
        prep [label="Preprocessing (preprocess.py)\nClean Inf/NaN, Dedup (2,522,362 Unique)\nWithhold 4 Classes (2,179) | 60/20/20 Split", fillcolor="#DBEAFE", color="#1D4ED8"];
        scaler [label="StandardScaler\nFit on Train Split (78 Features)", fillcolor="#E0F2FE", color="#0369A1"];
        rf_tr [label="Random Forest Trainer\n200 Trees | balanced | 11 Known Classes", fillcolor="#DCFCE7", color="#15803D"];
        if_tr [label="Isolation Forest Trainer\n200 Trees | 1,257,890 BENIGN Flows Only\nVal F1 Sweep -> Threshold t = 0.061102", fillcolor="#FEF3C7", color="#B45309"];
        man [label="Integrity Manifest (manifest.json)\nSHA-256 Digests + Optional Ed25519 .sig", fillcolor="#F3E8FF", color="#7E22CE"];

        raw -> prep -> scaler;
        scaler -> rf_tr -> man;
        scaler -> if_tr -> man;
    }

    subgraph cluster_online {
        label="Runtime Detection, Triage & Explainability";
        style="rounded,filled";
        fillcolor="#F8FAFC";
        color="#94A3B8";
        fontsize=12;
        fontname="DejaVu Sans";

        inp [label="Flow Telemetry Batch\n(Sample Parquet / CSV Upload / API)", fillcolor="#E2E8F0", color="#475569"];
        val [label="InputValidator (validator.py)\n78-Col Schema | <=50k Rows | <=50 MB | float32", fillcolor="#DBEAFE", color="#1D4ED8"];
        sec [label="Pre-Load Integrity Gate (security.py)\nVerify SHA-256 Before Unpickling", fillcolor="#F3E8FF", color="#7E22CE"];
        rf_inf [label="Random Forest Classifier\nPredicted Label + Max Confidence", fillcolor="#DCFCE7", color="#15803D"];
        if_inf [label="Isolation Forest Detector\nContinuous Anomaly Score", fillcolor="#FEF3C7", color="#B45309"];
        pol [label="Arbitration Policy Engine (policy.py)\nTiered (Default: HIGH / MED / LOW / INFO)\nBaseline | Balanced | Confidence-Gated", fillcolor="#FFE4E6", color="#BE123C"];
        grp [label="AlertGrouper (alert_grouper.py)\n60s Window or Gap<=50 | Queue KPIs", fillcolor="#E0E7FF", color="#4338CA"];
        xai [label="Explainability (explain.py)\nSHAP TreeExplainer + Z-Score Deviation", fillcolor="#CCFBF1", color="#0F766E"];
        ui [label="Streamlit SOC Console (6 Pages)\nOverview | Scan | Incidents | Investigate | History | Health", fillcolor="#1E293B", fontcolor="white", color="#0F172A"];

        inp -> val -> rf_inf;
        val -> if_inf;
        sec -> rf_inf [style=dashed];
        sec -> if_inf [style=dashed];
        rf_inf -> pol;
        if_inf -> pol;
        pol -> grp -> ui;
        pol -> xai -> ui;
    }

    man -> sec [label="Verifies Artifacts", style=dashed, color="#7E22CE"];
}
'''
    dot_file = OUT_DIR / "arch.dot"
    png_file = OUT_DIR / "fig_system_architecture.png"
    dot_file.write_text(dot_src, encoding="utf-8")
    subprocess.run(["dot", "-Tpng", "-Gdpi=220", str(dot_file), "-o", str(png_file)], check=True)
    dot_file.unlink()
    return png_file


def build_policy_tradeoff_chart(ev: dict) -> Path:
    W, H = 1500, 760
    img = Image.new("RGB", (W, H), "white")
    draw = ImageDraw.Draw(img)

    f_title = _font(28, bold=True)
    f_sub = _font(19, bold=False)
    f_lbl = _font(18, bold=True)
    f_ax = _font(16, bold=False)
    f_val = _font(15, bold=True)

    draw.text((60, 28), "Known-Attack Test Evaluation: RF-Only Baseline vs. Hybrid Policies (N = 504,037)", fill="#0F172A", font=f_title)
    draw.text((60, 66), "Actionable alerts (HIGH + MEDIUM) from reports/eval_results.json", fill="#475569", font=f_sub)

    rf = ev["known_attack_test"]["rf_only"]
    pc = ev["policy_comparison"]
    items = [
        ("RF-Only\nBaseline", rf["precision"] * 100, rf["recall"] * 100, rf["fpr"] * 100),
        ("Tiered\n(Rec.)", pc["tiered"]["actionable"]["precision"] * 100, pc["tiered"]["actionable"]["recall"] * 100, pc["tiered"]["actionable"]["fpr"] * 100),
        ("Balanced\n(t = 0)", pc["balanced"]["actionable"]["precision"] * 100, pc["balanced"]["actionable"]["recall"] * 100, pc["balanced"]["actionable"]["fpr"] * 100),
        ("Gated\n(Beta)", pc["confidence_gated"]["actionable"]["precision"] * 100, pc["confidence_gated"]["actionable"]["recall"] * 100, pc["confidence_gated"]["actionable"]["fpr"] * 100),
        ("Hybrid\nBaseline", pc["baseline"]["actionable"]["precision"] * 100, pc["baseline"]["actionable"]["recall"] * 100, pc["baseline"]["actionable"]["fpr"] * 100),
    ]

    # Two side-by-side panels: Left = Precision & Recall (0-100%), Right = FPR (0-12%)
    def draw_panel(x0, y0, pw, ph, title, series_specs, y_max, y_ticks):
        draw.text((x0, y0 - 34), title, fill="#1E293B", font=f_lbl)
        # Gridlines
        for yt in y_ticks:
            yy = y0 + ph - int((yt / y_max) * ph)
            draw.line([(x0, yy), (x0 + pw, yy)], fill="#E2E8F0", width=1)
            draw.text((x0 - 48, yy - 10), f"{yt:g}%", fill="#64748B", font=f_ax)
        draw.line([(x0, y0), (x0, y0 + ph)], fill="#64748B", width=2)
        draw.line([(x0, y0 + ph), (x0 + pw, y0 + ph)], fill="#64748B", width=2)

        n_groups = len(items)
        n_bars = len(series_specs)
        group_w = pw / n_groups
        bar_w = int(group_w * 0.68 / n_bars)
        gap = 4

        for gi, row in enumerate(items):
            cx = x0 + int((gi + 0.5) * group_w)
            total_bw = n_bars * bar_w + (n_bars - 1) * gap
            bx_start = cx - total_bw // 2
            for bi, (idx, color, _) in enumerate(series_specs):
                val = row[idx]
                bh = max(2, int((val / y_max) * ph))
                bx = bx_start + bi * (bar_w + gap)
                by = y0 + ph - bh
                draw.rectangle([bx, by, bx + bar_w, y0 + ph], fill=color)
                txt = f"{val:.2f}%" if (y_max < 50 or idx == 2) else f"{val:.1f}%"
                tw = draw.textlength(txt, font=f_val)
                draw.text((bx + bar_w / 2 - tw / 2, by - 22), txt, fill="#0F172A", font=f_val)

            # X label
            for li, line in enumerate(row[0].split("\n")):
                tw = draw.textlength(line, font=f_ax)
                draw.text((cx - tw / 2, y0 + ph + 10 + li * 20), line, fill="#1E293B", font=f_ax)

        # Legend
        lx = x0
        ly = y0 + ph + 62
        for _, color, label in series_specs:
            draw.rectangle([lx, ly, lx + 18, ly + 18], fill=color)
            draw.text((lx + 26, ly - 1), label, fill="#334155", font=f_ax)
            lx += int(draw.textlength(label, font=f_ax)) + 60

    draw_panel(80, 150, 740, 470, "Actionable Precision & Recall", [(1, "#2563EB", "Precision"), (2, "#0D9488", "Recall")], 108, [0, 20, 40, 60, 80, 100])
    draw_panel(920, 150, 520, 470, "Actionable False Positive Rate (FPR)", [(3, "#EA580C", "False Positive Rate")], 11.5, [0, 2, 4, 6, 8, 10])

    out = OUT_DIR / "fig_policy_tradeoff.png"
    img.save(out, dpi=(220, 220))
    return out


def build_withheld_chart(ev: dict) -> Path:
    W, H = 1400, 720
    img = Image.new("RGB", (W, H), "white")
    draw = ImageDraw.Draw(img)

    f_title = _font(28, bold=True)
    f_sub = _font(19, bold=False)
    f_ax = _font(17, bold=False)
    f_val = _font(16, bold=True)

    draw.text((60, 28), "Withheld Attack Categories (N = 2,179 Flows Never Seen by Classifier)", fill="#0F172A", font=f_title)
    draw.text((60, 66), "Detection rate (%) by Random Forest alone, Isolation Forest alone, and Tiered Actionable policy", fill="#475569", font=f_sub)

    w = ev["withheld_experiment"]["per_label"]
    t_w = ev["policy_comparison"]["tiered"]["withheld"]["per_label"]

    def find_key(d: dict, prefix: str) -> str:
        return next(k for k in d if k.startswith(prefix))

    cats = [
        ("Infiltration\n(n = 36)", "Infiltration"),
        ("Web Attack: SQLi\n(n = 21)", "Web Attack", "Sql"),
        ("Web Attack: Brute Force\n(n = 1,470)", "Web Attack", "Brute"),
        ("Web Attack: XSS\n(n = 652)", "Web Attack", "XSS"),
    ]

    rows = []
    for item in cats:
        label = item[0]
        if len(item) == 2:
            k = find_key(w, item[1])
        else:
            k = next(kk for kk in w if item[1] in kk and item[2] in kk)
        tot = w[k]["total"]
        rows.append((
            label,
            w[k]["rf_detected"] / tot * 100,
            w[k]["if_detected"] / tot * 100,
            t_w[k]["actionable"] * 100,
        ))

    x0, y0, pw, ph = 90, 130, 1240, 440
    y_max = 100.0
    for yt in [0, 20, 40, 60, 80, 100]:
        yy = y0 + ph - int((yt / y_max) * ph)
        draw.line([(x0, yy), (x0 + pw, yy)], fill="#E2E8F0", width=1)
        draw.text((x0 - 52, yy - 10), f"{yt}%", fill="#64748B", font=f_ax)
    draw.line([(x0, y0), (x0, y0 + ph)], fill="#64748B", width=2)
    draw.line([(x0, y0 + ph), (x0 + pw, y0 + ph)], fill="#64748B", width=2)

    specs = [
        (1, "#64748B", "Random Forest Alone"),
        (2, "#2563EB", "Isolation Forest Alone (t = 0.0611)"),
        (3, "#0D9488", "Hybrid Tiered Actionable (HIGH + MEDIUM)"),
    ]
    group_w = pw / len(rows)
    bar_w = 56
    gap = 10

    for gi, row in enumerate(rows):
        cx = x0 + int((gi + 0.5) * group_w)
        total_bw = 3 * bar_w + 2 * gap
        bx_start = cx - total_bw // 2
        for bi, (idx, color, _) in enumerate(specs):
            val = row[idx]
            bh = max(2, int((val / y_max) * ph))
            bx = bx_start + bi * (bar_w + gap)
            by = y0 + ph - bh
            draw.rectangle([bx, by, bx + bar_w, y0 + ph], fill=color)
            txt = f"{val:.2f}%"
            tw = draw.textlength(txt, font=f_val)
            draw.text((bx + bar_w / 2 - tw / 2, by - 22), txt, fill="#0F172A", font=f_val)
        for li, line in enumerate(row[0].split("\n")):
            tw = draw.textlength(line, font=f_ax)
            draw.text((cx - tw / 2, y0 + ph + 12 + li * 22), line, fill="#1E293B", font=f_ax)

    lx, ly = x0, y0 + ph + 84
    for _, color, lbl in specs:
        draw.rectangle([lx, ly, lx + 20, ly + 20], fill=color)
        draw.text((lx + 28, ly), lbl, fill="#334155", font=f_ax)
        lx += int(draw.textlength(lbl, font=f_ax)) + 70

    out = OUT_DIR / "fig_withheld_detection.png"
    img.save(out, dpi=(220, 220))
    return out


def main() -> None:
    ev = json.loads(EVAL_JSON.read_text(encoding="utf-8"))
    p1 = build_architecture_diagram()
    p2 = build_policy_tradeoff_chart(ev)
    p3 = build_withheld_chart(ev)
    print("Generated:", p1, p2, p3)


if __name__ == "__main__":
    main()
