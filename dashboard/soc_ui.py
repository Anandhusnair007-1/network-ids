"""
dashboard/soc_ui.py
===================
Presentation helpers for the SOC console: design tokens, CSS, and small HTML/Altair components.

Design notes
------------
* No external requests (fonts, CDNs): the console is meant for locked-down networks.
* Severity colours are fixed tokens and always paired with a text label, never colour alone.
* Benign traffic is deliberately the quietest colour so attention goes to alerts.
* Every dynamic string that reaches HTML goes through ``html.escape``.
"""

from __future__ import annotations

import html
import re

import altair as alt
import streamlit as st

# -- Tokens -------------------------------------------------------------------
BRAND = "#3FB6A8"
INK = "#0F1826"
PANEL = "#162236"
RULE = "#2A3A55"
TEXT = "#E6ECF5"
MUTED = "#9FB0C8"

SEVERITY = {
    "HIGH":   {"label": "High",   "color": "#E5484D"},
    "MEDIUM": {"label": "Medium", "color": "#F08A3C"},
    "LOW":    {"label": "Low",    "color": "#6E9BD1"},
    "INFO":   {"label": "Normal", "color": "#7C8BA3"},
}
SEV_ORDER = ["HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}

_METRIC_RULES = {
    "high": SEVERITY["HIGH"]["color"],
    "medium": SEVERITY["MEDIUM"]["color"],
    "low": SEVERITY["LOW"]["color"],
    "info": SEVERITY["INFO"]["color"],
    "good": BRAND,
    "plain": RULE,
}

CSS = f"""
<style>
.block-container {{ padding-top: 2.4rem; max-width: 1280px; }}
footer {{ visibility: hidden; }}
h1 {{ font-weight: 650; letter-spacing: -0.01em; }}
h2, h3 {{ font-weight: 600; letter-spacing: -0.005em; }}
[data-testid="stMetric"] {{
    border-left: 3px solid var(--rule, {RULE});
    padding: 2px 0 2px 14px;
}}
[data-testid="stMetricValue"] {{ font-variant-numeric: tabular-nums; font-weight: 600; }}
[data-testid="stMetricLabel"] {{ color: {MUTED}; }}
.situation {{ font-size: 1.15rem; line-height: 1.55; max-width: 72ch; margin: 0.1rem 0 1.5rem; }}
.situation b {{ font-weight: 650; }}
.note {{ color: {MUTED}; font-size: 0.92rem; line-height: 1.5; max-width: 78ch; }}
.sev {{ display: inline-flex; align-items: center; gap: 7px; font-weight: 600; }}
.sev::before {{ content: ""; width: 9px; height: 9px; border-radius: 50%; background: var(--c); }}
.sevbar {{ display: flex; height: 16px; border-radius: 3px; overflow: hidden; background: #1B2A44; margin: 0.2rem 0 0.5rem; }}
.sevbar > span {{ display: block; height: 100%; }}
.sevlegend {{ display: flex; flex-wrap: wrap; gap: 18px; font-size: 0.92rem; margin-bottom: 1.2rem; }}
.sevlegend .n {{ font-variant-numeric: tabular-nums; color: {MUTED}; margin-left: 4px; }}
.ruler {{ position: relative; margin: 1.9rem 0.4rem 3.2rem; }}
.ruler .track {{ display: flex; height: 12px; border-radius: 3px; overflow: hidden; }}
.ruler .track > span {{ display: block; height: 100%; }}
.ruler .marker {{ position: absolute; top: -6px; width: 3px; height: 24px; background: {TEXT};
    border-radius: 2px; transform: translateX(-1px); }}
.ruler .marker > b {{ position: absolute; bottom: 28px; left: 50%; transform: translateX(-50%);
    white-space: nowrap; font-size: 0.9rem; font-variant-numeric: tabular-nums; }}
.ruler .tick {{ position: absolute; top: 16px; width: 1px; height: 8px; background: {MUTED}; }}
.ruler .tick > i {{ position: absolute; top: 12px; left: 0; transform: translateX(-50%);
    white-space: nowrap; font-style: normal; font-size: 0.8rem; color: {MUTED}; text-align: center;
    font-variant-numeric: tabular-nums; }}
.ruler .ends {{ display: flex; justify-content: space-between; font-size: 0.8rem; color: {MUTED}; margin-top: 2.6rem; }}
{"".join(f'[class*="st-key-mrule-{k}-"] {{ --rule: {v}; }}' for k, v in _METRIC_RULES.items())}
</style>
"""


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "m"


# -- Components ---------------------------------------------------------------
def situation(markdown_html: str) -> None:
    """One plain-language sentence that opens each page. Caller passes pre-escaped HTML."""
    st.markdown(f'<p class="situation">{markdown_html}</p>', unsafe_allow_html=True)


def note(text: str) -> None:
    st.markdown(f'<p class="note">{esc(text)}</p>', unsafe_allow_html=True)


def sev_chip(sev: str) -> str:
    meta = SEVERITY.get(sev, SEVERITY["INFO"])
    return f'<span class="sev" style="--c:{meta["color"]}">{esc(meta["label"])}</span>'


def metric(label: str, value: str, tone: str = "plain", help: str | None = None, delta: str | None = None) -> None:
    """st.metric with a left rule whose colour encodes meaning (severity or 'good')."""
    with st.container(key=f"mrule-{tone}-{slug(label)}"):
        st.metric(label, value, delta=delta, help=help, delta_color="off")


def severity_bar(counts: dict[str, int]) -> None:
    total = sum(counts.values()) or 1
    segs, legend = [], []
    for sev in SEV_ORDER:
        n = int(counts.get(sev, 0))
        meta = SEVERITY[sev]
        if n:
            segs.append(
                f'<span style="width:{max(n / total * 100, 0.6):.3f}%;background:{meta["color"]}" '
                f'title="{esc(meta["label"])}: {n:,}"></span>'
            )
        legend.append(
            f'<span><span class="sev" style="--c:{meta["color"]}">{esc(meta["label"])}</span>'
            f'<span class="n">{n:,}</span></span>'
        )
    st.markdown(
        f'<div class="sevbar" role="img" aria-label="Severity mix">{"".join(segs)}</div>'
        f'<div class="sevlegend">{"".join(legend)}</div>',
        unsafe_allow_html=True,
    )


def score_ruler(score: float, bands: list[tuple[float, str]], lo: float = -0.25, hi: float = 0.25) -> None:
    """
    Anomaly-score ruler. ``bands`` is an ascending list of (upper_bound, severity) regions;
    everything above the last bound is Normal. Lower scores are more anomalous.
    """
    span = hi - lo

    def pct(v: float) -> float:
        return (min(max(v, lo), hi) - lo) / span * 100

    edges, prev, parts = [], lo, []
    for bound, sev in bands:
        parts.append((pct(prev), pct(bound), SEVERITY[sev]["color"]))
        edges.append(bound)
        prev = bound
    parts.append((pct(prev), 100.0, SEVERITY["INFO"]["color"]))

    track = "".join(
        f'<span style="width:{b - a:.3f}%;background:{c}"></span>' for a, b, c in parts if b - a > 0
    )
    ticks = "".join(
        f'<div class="tick" style="left:{pct(bound):.3f}%"><i>{bound:+.3f}</i></div>' for bound, _ in bands
    )
    clipped = " (off scale)" if score < lo or score > hi else ""
    st.markdown(
        '<div class="ruler" role="img" '
        f'aria-label="Anomaly score {score:.3f}; lower is more unusual">'
        f'<div class="track">{track}</div>{ticks}'
        f'<div class="marker" style="left:{pct(score):.3f}%"><b>{score:+.3f}{clipped}</b></div>'
        '<div class="ends"><span>more unusual</span><span>more typical</span></div></div>',
        unsafe_allow_html=True,
    )


# -- Altair -------------------------------------------------------------------
def sev_scale(order: list[str] | None = None) -> alt.Scale:
    keys = order or SEV_ORDER
    return alt.Scale(domain=[SEVERITY[k]["label"] for k in keys], range=[SEVERITY[k]["color"] for k in keys])


def style(chart: alt.Chart | alt.LayerChart, height: int = 300) -> alt.Chart | alt.LayerChart:
    return (
        chart.properties(height=height)
        .configure(background="transparent")
        .configure_view(stroke=None)
        .configure_axis(labelColor=MUTED, titleColor=MUTED, gridColor="#1F2E48", domainColor=RULE, tickColor=RULE,
                        labelFontSize=12, titleFontSize=12, titleFontWeight="normal", labelLimit=320)
        .configure_legend(labelColor=TEXT, titleColor=MUTED, labelFontSize=12, titleFontSize=12)
        .configure_title(color=TEXT)
    )
