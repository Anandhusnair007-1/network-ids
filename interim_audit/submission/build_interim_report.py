#!/usr/bin/env python3
"""
Build the MCA S3 Interim Report DOCX and PDF directly from the official
Amrita template (/home/anandhu/Downloads/Interim Report Template - S3.docx)
into /home/anandhu/projects/interim_audit/submission/.
"""

from __future__ import annotations

import copy
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from PIL import Image

TEMPLATE = Path("/home/anandhu/Downloads/Interim Report Template - S3.docx")
SUBMISSION_DIR = Path("/home/anandhu/projects/interim_audit/submission")
FIG_DIR = SUBMISSION_DIR / "figures"
OUT_DOCX = SUBMISSION_DIR / "Network_IDS_Interim_Report_Anandhu_S_Nair.docx"
OUT_PDF = SUBMISSION_DIR / "Network_IDS_Interim_Report_Anandhu_S_Nair.pdf"

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
WP_NS = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
PIC_NS = "http://schemas.openxmlformats.org/drawingml/2006/picture"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"

NS_PREFIXES = {
    "wpc": "http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas",
    "mc": "http://schemas.openxmlformats.org/markup-compatibility/2006",
    "o": "urn:schemas-microsoft-com:office:office",
    "r": R_NS,
    "m": "http://schemas.openxmlformats.org/officeDocument/2006/math",
    "v": "urn:schemas-microsoft-com:vml",
    "wp14": "http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing",
    "wp": WP_NS,
    "w10": "urn:schemas-microsoft-com:office:word",
    "w": W_NS,
    "w14": "http://schemas.microsoft.com/office/word/2010/wordml",
    "w15": "http://schemas.microsoft.com/office/word/2012/wordml",
    "wpg": "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup",
    "wpi": "http://schemas.microsoft.com/office/word/2010/wordprocessingInk",
    "wne": "http://schemas.microsoft.com/office/word/2006/wordml",
    "wps": "http://schemas.microsoft.com/office/word/2010/wordprocessingShape",
    "a": A_NS,
    "a14": "http://schemas.microsoft.com/office/drawing/2010/main",
    "pic": PIC_NS,
}
for _pfx, _uri in NS_PREFIXES.items():
    ET.register_namespace(_pfx, _uri)


def w_tag(name: str) -> str:
    return f"{{{W_NS}}}{name}"


def _rpr(sz_half_pts: int = 24, bold: bool = False, italic: bool = False, color: str = "000000") -> ET.Element:
    rPr = ET.Element(w_tag("rPr"))
    rFonts = ET.SubElement(rPr, w_tag("rFonts"))
    for k in ("ascii", "eastAsia", "hAnsi", "cs"):
        rFonts.set(w_tag(k), "Times New Roman")
    if bold:
        ET.SubElement(rPr, w_tag("b"))
    if italic:
        ET.SubElement(rPr, w_tag("i"))
    c = ET.SubElement(rPr, w_tag("color"))
    c.set(w_tag("val"), color)
    sz = ET.SubElement(rPr, w_tag("sz"))
    sz.set(w_tag("val"), str(sz_half_pts))
    szCs = ET.SubElement(rPr, w_tag("szCs"))
    szCs.set(w_tag("val"), str(sz_half_pts))
    return rPr


def make_run(text: str, sz_hp: int = 24, bold: bool = False, italic: bool = False, color: str = "000000") -> ET.Element:
    r = ET.Element(w_tag("r"))
    r.append(_rpr(sz_hp, bold=bold, italic=italic, color=color))
    t = ET.SubElement(r, w_tag("t"))
    t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    t.text = text
    return r


def make_p(
    runs: list[tuple[str, bool, bool]] | str,
    sz_hp: int = 24,
    align: str = "both",
    before: int = 0,
    after: int = 100,
    line: int = 264,
    indent_left: int = 0,
    hanging: int = 0,
    keep_next: bool = False,
    page_break_before: bool = False,
    color: str = "000000",
) -> ET.Element:
    p = ET.Element(w_tag("p"))
    pPr = ET.SubElement(p, w_tag("pPr"))
    pStyle = ET.SubElement(pPr, w_tag("pStyle"))
    pStyle.set(w_tag("val"), "Normal0")
    if keep_next:
        ET.SubElement(pPr, w_tag("keepNext"))
    if page_break_before:
        ET.SubElement(pPr, w_tag("pageBreakBefore"))
    sp = ET.SubElement(pPr, w_tag("spacing"))
    sp.set(w_tag("before"), str(before))
    sp.set(w_tag("after"), str(after))
    sp.set(w_tag("line"), str(line))
    sp.set(w_tag("lineRule"), "auto")
    if indent_left or hanging:
        ind = ET.SubElement(pPr, w_tag("ind"))
        if indent_left:
            ind.set(w_tag("left"), str(indent_left))
        if hanging:
            ind.set(w_tag("hanging"), str(hanging))
    jc = ET.SubElement(pPr, w_tag("jc"))
    jc.set(w_tag("val"), align)

    if isinstance(runs, str):
        p.append(make_run(runs, sz_hp=sz_hp, color=color))
    else:
        for txt, b, it in runs:
            p.append(make_run(txt, sz_hp=sz_hp, bold=b, italic=it, color=color))
    return p


def heading(text: str, level: int = 1, page_break: bool = False) -> ET.Element:
    if level == 1:
        return make_p(
            [(text, True, False)],
            sz_hp=26,
            align="left",
            before=220,
            after=100,
            line=240,
            keep_next=True,
            page_break_before=page_break,
            color="1A365D",
        )
    return make_p(
        [(text, True, False)],
        sz_hp=24,
        align="left",
        before=160,
        after=70,
        line=240,
        keep_next=True,
        page_break_before=page_break,
        color="1E293B",
    )


def bullet(lead: str, body_text: str) -> ET.Element:
    runs: list[tuple[str, bool, bool]] = [("•  ", True, False)]
    if lead:
        runs.append((lead + ": ", True, False))
    runs.append((body_text, False, False))
    return make_p(runs, sz_hp=23, align="both", before=0, after=65, line=255, indent_left=360, hanging=210)


def body_p(runs: list[tuple[str, bool, bool]] | str, after: int = 95, sz_hp: int = 23) -> ET.Element:
    return make_p(runs, sz_hp=sz_hp, align="both", before=0, after=after, line=260)


def make_table(headers: list[str], rows: list[list[str]], col_widths_dxa: list[int], aligns: list[str] | None = None) -> ET.Element:
    tbl = ET.Element(w_tag("tbl"))
    tblPr = ET.SubElement(tbl, w_tag("tblPr"))
    tblW = ET.SubElement(tblPr, w_tag("tblW"))
    tblW.set(w_tag("w"), str(sum(col_widths_dxa)))
    tblW.set(w_tag("type"), "dxa")
    borders = ET.SubElement(tblPr, w_tag("tblBorders"))
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        b = ET.SubElement(borders, w_tag(edge))
        b.set(w_tag("val"), "single")
        b.set(w_tag("sz"), "6")
        b.set(w_tag("space"), "0")
        b.set(w_tag("color"), "CBD5E1")
    tblLayout = ET.SubElement(tblPr, w_tag("tblLayout"))
    tblLayout.set(w_tag("type"), "fixed")

    tblGrid = ET.SubElement(tbl, w_tag("tblGrid"))
    for w in col_widths_dxa:
        gc = ET.SubElement(tblGrid, w_tag("gridCol"))
        gc.set(w_tag("w"), str(w))

    def build_row(cells: list[str], is_hdr: bool, shade: str | None) -> ET.Element:
        tr = ET.Element(w_tag("tr"))
        if is_hdr:
            trPr = ET.SubElement(tr, w_tag("trPr"))
            ET.SubElement(trPr, w_tag("tblHeader"))
            ET.SubElement(trPr, w_tag("cantSplit"))
        else:
            trPr = ET.SubElement(tr, w_tag("trPr"))
            ET.SubElement(trPr, w_tag("cantSplit"))
        for idx, text in enumerate(cells):
            tc = ET.SubElement(tr, w_tag("tc"))
            tcPr = ET.SubElement(tc, w_tag("tcPr"))
            tcW = ET.SubElement(tcPr, w_tag("tcW"))
            tcW.set(w_tag("w"), str(col_widths_dxa[idx]))
            tcW.set(w_tag("type"), "dxa")
            if shade:
                shd = ET.SubElement(tcPr, w_tag("shd"))
                shd.set(w_tag("val"), "clear")
                shd.set(w_tag("color"), "auto")
                shd.set(w_tag("fill"), shade)
            mar = ET.SubElement(tcPr, w_tag("tcMar"))
            for side, val in (("top", "75"), ("bottom", "75"), ("left", "105"), ("right", "105")):
                m = ET.SubElement(mar, w_tag(side))
                m.set(w_tag("w"), val)
                m.set(w_tag("type"), "dxa")
            vAlign = ET.SubElement(tcPr, w_tag("vAlign"))
            vAlign.set(w_tag("val"), "center")
            jc = "center" if is_hdr else (aligns[idx] if aligns else "left")
            p = make_p(
                [(text, is_hdr, False)],
                sz_hp=20 if not is_hdr else 21,
                align=jc,
                before=0,
                after=0,
                line=230,
                color="FFFFFF" if is_hdr else "0F172A",
            )
            tc.append(p)
        return tr

    tbl.append(build_row(headers, True, "1A365D"))
    for r_idx, row in enumerate(rows):
        tbl.append(build_row(row, False, "F8FAFC" if r_idx % 2 == 1 else None))
    return tbl


def make_abstract_box(abstract_text: str) -> ET.Element:
    tbl = ET.Element(w_tag("tbl"))
    tblPr = ET.SubElement(tbl, w_tag("tblPr"))
    tblW = ET.SubElement(tblPr, w_tag("tblW"))
    tblW.set(w_tag("w"), "9360")
    tblW.set(w_tag("type"), "dxa")
    borders = ET.SubElement(tblPr, w_tag("tblBorders"))
    for edge in ("top", "left", "bottom", "right"):
        b = ET.SubElement(borders, w_tag(edge))
        b.set(w_tag("val"), "single")
        b.set(w_tag("sz"), "8")
        b.set(w_tag("space"), "0")
        b.set(w_tag("color"), "334155")
    grid = ET.SubElement(tbl, w_tag("tblGrid"))
    gc = ET.SubElement(grid, w_tag("gridCol"))
    gc.set(w_tag("w"), "9360")
    tr = ET.SubElement(tbl, w_tag("tr"))
    tc = ET.SubElement(tr, w_tag("tc"))
    tcPr = ET.SubElement(tc, w_tag("tcPr"))
    tcW = ET.SubElement(tcPr, w_tag("tcW"))
    tcW.set(w_tag("w"), "9360")
    tcW.set(w_tag("type"), "dxa")
    shd = ET.SubElement(tcPr, w_tag("shd"))
    shd.set(w_tag("val"), "clear")
    shd.set(w_tag("color"), "auto")
    shd.set(w_tag("fill"), "F8FAFC")
    mar = ET.SubElement(tcPr, w_tag("tcMar"))
    for side, val in (("top", "140"), ("bottom", "140"), ("left", "180"), ("right", "180")):
        m = ET.SubElement(mar, w_tag(side))
        m.set(w_tag("w"), val)
        m.set(w_tag("type"), "dxa")
    tc.append(make_p(abstract_text, sz_hp=23, align="both", before=0, after=0, line=260))
    return tbl


def make_figure(r_id: str, img_path: Path, width_in: float, caption: str, doc_id: int) -> list[ET.Element]:
    with Image.open(img_path) as im:
        w_px, h_px = im.size
    cx = int(width_in * 914400)
    cy = int(cx * (h_px / w_px))

    p_img = ET.Element(w_tag("p"))
    pPr = ET.SubElement(p_img, w_tag("pPr"))
    pStyle = ET.SubElement(pPr, w_tag("pStyle"))
    pStyle.set(w_tag("val"), "Normal0")
    ET.SubElement(pPr, w_tag("keepNext"))
    sp = ET.SubElement(pPr, w_tag("spacing"))
    sp.set(w_tag("before"), "120")
    sp.set(w_tag("after"), "60")
    jc = ET.SubElement(pPr, w_tag("jc"))
    jc.set(w_tag("val"), "center")

    r = ET.SubElement(p_img, w_tag("r"))
    drawing = ET.SubElement(r, w_tag("drawing"))
    inline = ET.SubElement(drawing, f"{{{WP_NS}}}inline")
    for attr in ("distT", "distB", "distL", "distR"):
        inline.set(attr, "0")
    extent = ET.SubElement(inline, f"{{{WP_NS}}}extent")
    extent.set("cx", str(cx))
    extent.set("cy", str(cy))
    eff = ET.SubElement(inline, f"{{{WP_NS}}}effectExtent")
    for attr in ("l", "t", "r", "b"):
        eff.set(attr, "0")
    docPr = ET.SubElement(inline, f"{{{WP_NS}}}docPr")
    docPr.set("id", str(doc_id))
    docPr.set("name", img_path.name)
    cNv = ET.SubElement(inline, f"{{{WP_NS}}}cNvGraphicFramePr")
    locks = ET.SubElement(cNv, f"{{{A_NS}}}graphicFrameLocks")
    locks.set("noChangeAspect", "1")
    graphic = ET.SubElement(inline, f"{{{A_NS}}}graphic")
    gdata = ET.SubElement(graphic, f"{{{A_NS}}}graphicData")
    gdata.set("uri", PIC_NS)
    pic = ET.SubElement(gdata, f"{{{PIC_NS}}}pic")
    nvPic = ET.SubElement(pic, f"{{{PIC_NS}}}nvPicPr")
    cNvPr = ET.SubElement(nvPic, f"{{{PIC_NS}}}cNvPr")
    cNvPr.set("id", str(doc_id))
    cNvPr.set("name", img_path.name)
    ET.SubElement(nvPic, f"{{{PIC_NS}}}cNvPicPr")
    blipFill = ET.SubElement(pic, f"{{{PIC_NS}}}blipFill")
    blip = ET.SubElement(blipFill, f"{{{A_NS}}}blip")
    blip.set(f"{{{R_NS}}}embed", r_id)
    stretch = ET.SubElement(blipFill, f"{{{A_NS}}}stretch")
    ET.SubElement(stretch, f"{{{A_NS}}}fillRect")
    spPr = ET.SubElement(pic, f"{{{PIC_NS}}}spPr")
    xfrm = ET.SubElement(spPr, f"{{{A_NS}}}xfrm")
    off = ET.SubElement(xfrm, f"{{{A_NS}}}off")
    off.set("x", "0")
    off.set("y", "0")
    ext = ET.SubElement(xfrm, f"{{{A_NS}}}ext")
    ext.set("cx", str(cx))
    ext.set("cy", str(cy))
    prstGeom = ET.SubElement(spPr, f"{{{A_NS}}}prstGeom")
    prstGeom.set("prst", "rect")
    ET.SubElement(prstGeom, f"{{{A_NS}}}avLst")

    p_cap = make_p([(caption, False, True)], sz_hp=20, align="center", before=0, after=140, line=240, color="334155")
    return [p_img, p_cap]


def build_footer_xml() -> bytes:
    ftr = ET.Element(w_tag("ftr"))
    p = ET.SubElement(ftr, w_tag("p"))
    pPr = ET.SubElement(p, w_tag("pPr"))
    tabs = ET.SubElement(pPr, w_tag("tabs"))
    tab = ET.SubElement(tabs, w_tag("tab"))
    tab.set(w_tag("val"), "right")
    tab.set(w_tag("pos"), "9360")
    p.append(make_run("Case Study 25CSA698A — Interim Report (Anandhu S Nair)", sz_hp=18, color="64748B"))
    r_tab = ET.SubElement(p, w_tag("r"))
    r_tab.append(_rpr(18, color="64748B"))
    ET.SubElement(r_tab, w_tag("tab"))
    p.append(make_run("Page ", sz_hp=18, color="64748B"))

    for fld in ("PAGE", "NUMPAGES"):
        r1 = ET.SubElement(p, w_tag("r"))
        r1.append(_rpr(18, color="64748B"))
        fc1 = ET.SubElement(r1, w_tag("fldChar"))
        fc1.set(w_tag("fldCharType"), "begin")
        r2 = ET.SubElement(p, w_tag("r"))
        r2.append(_rpr(18, color="64748B"))
        instr = ET.SubElement(r2, w_tag("instrText"))
        instr.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        instr.text = f" {fld} "
        r3 = ET.SubElement(p, w_tag("r"))
        r3.append(_rpr(18, color="64748B"))
        fc2 = ET.SubElement(r3, w_tag("fldChar"))
        fc2.set(w_tag("fldCharType"), "separate")
        r4 = ET.SubElement(p, w_tag("r"))
        r4.append(_rpr(18, color="64748B"))
        t4 = ET.SubElement(r4, w_tag("t"))
        t4.text = "1"
        r5 = ET.SubElement(p, w_tag("r"))
        r5.append(_rpr(18, color="64748B"))
        fc3 = ET.SubElement(r5, w_tag("fldChar"))
        fc3.set(w_tag("fldCharType"), "end")
        if fld == "PAGE":
            p.append(make_run(" of ", sz_hp=18, color="64748B"))

    return ET.tostring(ftr, encoding="utf-8", xml_declaration=True)


def build_report() -> None:
    SUBMISSION_DIR.mkdir(parents=True, exist_ok=True)
    abstract_text = (
        "Modern enterprise networks face escalating risks from automated floods, credential brute-forcing, and stealthy "
        "lateral infiltration. Conventional signature-based Network Intrusion Detection Systems (NIDS) achieve low false-alarm "
        "rates on known threats but fail when no rule matches an emerging attack. Conversely, supervised machine learning "
        "classifiers perform well on training categories yet operate under a closed-world constraint, frequently labeling "
        "unfamiliar attack classes as benign. This interim case study presents the design, implementation, and empirical "
        "evaluation of a hybrid ML-based NIDS combining a supervised Random Forest classifier (200 trees, balanced class "
        "weights) with a semi-supervised Isolation Forest anomaly detector (200 trees) on the CIC-IDS2017 benchmark "
        "(2,830,743 raw flows; 2,522,362 deduplicated flows across 78 statistical features). To study novel-pattern "
        "detection under controlled conditions without data leakage, four attack categories—Infiltration and three Web "
        "Attack variants (2,179 flows)—were withheld from supervised training, while Isolation Forest was trained strictly "
        "on 1,257,890 benign flows with its threshold (0.061102) calibrated on an independent validation split. The system "
        "integrates SHAP TreeExplainer attributions, z-score feature deviations, and temporal alert grouping inside a "
        "Streamlit console. On 504,037 test flows, the hybrid system preserves 99.94%–99.95% known-attack recall, controls "
        "false alarms via tiered severity (86.30% actionable precision, 3.21% FPR), and flags 31 of 36 withheld Infiltration "
        "flows while exposing flow-level limits on HTTP payload attacks."
    )
    wc = len(abstract_text.split())
    assert wc <= 250, f"Abstract has {wc} words (> 250)"
    print(f"Abstract word count: {wc} / 250")

    with zipfile.ZipFile(TEMPLATE, "r") as zin:
        doc_bytes = zin.read("word/document.xml")
        rels_bytes = zin.read("word/_rels/document.xml.rels")
        ct_bytes = zin.read("[Content_Types].xml")
        files = {name: zin.read(name) for name in zin.namelist()}

    root = ET.fromstring(doc_bytes)
    body = root.find(w_tag("body"))
    assert body is not None

    # Preserve header elements [0..9] (invocation, logo, Case Study 25CSA698A, Interim Report, metadata)
    # and fill Project Title, Student Name, Roll No. cleanly.
    header_els = [copy.deepcopy(body[i]) for i in range(10)]
    header_els[7].append(make_run("Network Intrusion Detection System (IDS)", sz_hp=24, bold=False))
    # Trim trailing spaces on Student Name run, then append name
    for t in header_els[8].iter(w_tag("t")):
        if t.text and t.text.strip() == "":
            t.text = " "
    header_els[8].append(make_run(" Anandhu S Nair", sz_hp=24, bold=False))
    header_els[9].append(make_run(" AA.SC.P2MCA25070089", sz_hp=24, bold=False))

    sect_pr = copy.deepcopy(body[-1])
    # Prepare sign-off table from body[37], stripping floating tblpPr and filling Date & Name
    sign_tbl = copy.deepcopy(body[37])
    tblPr_s = sign_tbl.find(w_tag("tblPr"))
    if tblPr_s is not None:
        tblp = tblPr_s.find(w_tag("tblpPr"))
        if tblp is not None:
            tblPr_s.remove(tblp)
    trs = sign_tbl.findall(w_tag("tr"))
    trs[0].find(w_tag("tc")).find(w_tag("p")).append(make_run("26 November 2026", sz_hp=24, bold=False))
    trs[1].find(w_tag("tc")).find(w_tag("p")).append(make_run("  Anandhu S Nair", sz_hp=24, bold=False))

    # Clear body and rebuild
    for child in list(body):
        body.remove(child)
    for el in header_els:
        body.append(el)

    # ---- Abstract ----
    body.append(heading("Abstract", level=1))
    body.append(make_abstract_box(abstract_text))
    body.append(body_p([("Keywords: ", True, False), ("Network Intrusion Detection System, Hybrid Machine Learning, Random Forest, Isolation Forest, CIC-IDS2017, Withheld-Category Evaluation, SHAP Explainability, Alert Triage.", False, True)], after=120, sz_hp=21))

    # ---- Objectives ----
    body.append(heading("Objectives", level=1))
    body.append(body_p("The primary goal of this case study is to build, benchmark, and critically evaluate a hybrid machine-learning Network Intrusion Detection System that pairs supervised attack classification with benign-baseline anomaly detection and analyst-oriented explanations. Specific objectives are grouped by current interim completion status:"))
    body.append(heading("Completed Core Objectives", level=2))
    body.append(bullet("Data Hygiene and Leakage-Safe Splitting", "Audit the full CIC-IDS2017 corpus (2,830,743 raw rows), eliminate infinite/missing artifacts, drop 308,381 exact duplicates, and establish a stratified 60/20/20 split alongside a strictly isolated 2,179-flow withheld-attack evaluation partition."))
    body.append(bullet("Dual-Engine Hybrid Detection", "Train a class-balanced 200-tree Random Forest classifier on 11 known traffic categories and a 200-tree Isolation Forest exclusively on benign flows with validation-calibrated thresholding, unified under configurable severity arbitration policies."))
    body.append(bullet("Controlled Unseen-Category Benchmarking", "Compare the hybrid detector against a Random Forest-only baseline across known attacks and four withheld attack categories to quantify both detection gains and false-alarm overhead."))
    body.append(bullet("Explainable Triage and Verification Console", "Integrate local SHAP TreeExplainer attributions, feature z-score deviations, alert grouping, and SHA-256 model integrity verification into a multipage Streamlit console."))
    body.append(heading("Remaining Final-Phase Objectives", level=2))
    body.append(bullet("Environment Restoration and Test Verification", "Resolve the host Python 3.14 versus virtualenv Python 3.12 interpreter mismatch so all eight pytest suites and headless Streamlit smoke checks execute cleanly."))
    body.append(bullet("Reproducible Latency and Confusion-Matrix Benchmarking", "Implement a standardized timing benchmark script and persist binary/multiclass confusion matrices and per-class test metrics into structured JSON outputs before the final demonstration and viva."))

    # ---- Scope ----
    body.append(heading("Scope", level=1, page_break=True))
    body.append(body_p("This academic case study focuses on offline statistical flow-level intrusion detection using open-source machine learning and visualization tooling. Establishing clear operational boundaries prevents overstatement of system capabilities:"))
    body.append(bullet("Dataset Scope", "Analysis is confined to the eight MachineLearningCVE CSV captures from the public CIC-IDS2017 dataset, comprising 78 numeric transport, timing, flag, packet-length, and subflow statistics plus ground-truth labels."))
    body.append(bullet("Attack Coverage Scope", "The supervised Random Forest models 10 known attack classes (DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, DDoS, PortScan, Bot, Heartbleed, FTP-Patator, and SSH-Patator) plus BENIGN traffic. Four additional categories—Infiltration (36 flows) and three Web Attack variants (Brute Force, XSS, and SQL Injection; 2,143 flows)—are deliberately excluded from classifier training to test anomaly detection."))
    body.append(bullet("Algorithmic and Interface Scope", "The core architecture covers StandardScaler normalization, Random Forest, Isolation Forest, four vectorized arbitration policies (Tiered, Baseline, Balanced, and Confidence-Gated), temporal/sequential alert grouping, SHAP TreeExplainer, baseline z-score deviation, and the Streamlit SOC console. Optional deployment utilities (FastAPI scoring service, SQLite alert store, SIEM export, PSI drift monitoring, and Docker manifests) were prototyped in the repository as engineering extensions outside the core academic deliverable."))
    body.append(bullet("Evaluation Boundaries", "Performance is measured on stratified held-out test flows (504,037 records) and the 2,179-flow withheld split using precision, recall, F1-score, false positive rate, and alert volume. Note that the withheld-category experiment evaluates detection of traffic patterns excluded from training within CIC-IDS2017; it does not constitute proof of general real-world zero-day detection."))
    body.append(bullet("Key Technical Limitations", "Because inputs are bidirectional flow summaries rather than raw packets or decrypted application payloads, the platform cannot inspect HTTP parameters or TLS payloads. Consequently, Layer-7 web attacks show low transport-level separability (6%–19% detection) and require a complementary Web Application Firewall (WAF). Thresholds calibrated on 2017 lab traffic require recalibration before any live enterprise use."))

    # ---- Introduction ----
    body.append(heading("Introduction", level=1, page_break=True))
    body.append(body_p("Enterprise computing infrastructure relies on continuous network connectivity across cloud workloads, campus servers, and remote endpoints. Alongside legitimate traffic, automated scanning, volumetric denial-of-service floods, credential stuffing, and lateral reconnaissance persistently target exposed services. Network Intrusion Detection Systems (NIDS) monitor traffic telemetry to identify unauthorized behavior early enough for security analysts to contain damage."))
    body.append(body_p("Historically, operational perimeter monitoring has centered on rule-driven signature engines such as Snort and Suricata. Deterministic rules match known byte sequences, malformed headers, or fixed protocol patterns with very low false-alarm rates, typically below 0.1%. However, writing and maintaining signatures is inherently reactive: polymorphic attack variants, newly disclosed exploits, and low-rate lateral movements without matching rules pass undetected."))
    body.append(body_p("To overcome static rule rigidity, machine learning approaches train statistical models over summarized network flow records (for example, flow duration, inter-arrival variance, flag counts, and byte ratios). Supervised classifiers such as Random Forests routinely achieve above 99% accuracy on public benchmarks when test traffic mirrors training attack distributions. Yet in realistic environments, supervised models face a structural closed-world limitation: every incoming flow must be assigned to one of the classes observed during training. When a previously unseen attack family arrives, a confident classifier frequently maps it to the nearest normal cluster, yielding silent false negatives."))
    body.append(body_p("Unsupervised anomaly detectors address this closed-world blind spot by modeling only normal (BENIGN) behavior and flagging statistical outliers. While conceptually appealing for catching unfamiliar behavior, anomaly detection in isolation exhibits an operational drawback: normal network traffic is highly diverse, so flagging every geometric deviation inflates false positive rates to levels that overwhelm Security Operations Center (SOC) analysts. Furthermore, raw anomaly scores and complex ensemble predictions offer little explanation on their own, leaving human responders without clear feature-level evidence."))
    body.append(body_p("This case study investigates how a hybrid architecture—combining high-precision Random Forest classification with benign-trained Isolation Forest anomaly detection, policy-based severity tiering, alert consolidation, and SHAP explainability—balances threat visibility against analyst workload. The research is guided by four concrete questions:"))
    body.append(bullet("RQ1 (Supervised Fidelity)", "How accurately does a class-balanced Random Forest classify known CIC-IDS2017 attack families across multiclass and binary metrics after strict deduplication?"))
    body.append(bullet("RQ2 (Unseen-Category Visibility)", "Can an Isolation Forest trained solely on benign traffic detect attack categories completely withheld from supervised training?"))
    body.append(bullet("RQ3 (False-Alarm Cost and Arbitration)", "What false-positive penalty is introduced by adding anomaly detection, and how effectively can tiered severity policies separate high-confidence alerts from marginal noise?"))
    body.append(bullet("RQ4 (Triage and Explainability)", "How effectively do local SHAP TreeExplainer attributions, feature z-score deviations, and temporal alert grouping support analyst investigation?"))
    body.append(body_p("The remainder of this interim report is structured as follows. The Background section reviews foundational detection paradigms and model families. Related Works summarizes ten peer-reviewed studies and pinpoints the research gap. Detailed Problem Statement contrasts current detection weaknesses against desired system behavior. Methods and Algorithms details the preprocessing pipeline, Random Forest and Isolation Forest training, hybrid policies, explainability, alert grouping, and the Streamlit interface. Finally, Expected Results presents verified interim metrics alongside remaining final-phase verification tasks."))

    # ---- Background ----
    body.append(heading("Background", level=1))
    body.append(body_p("Modern intrusion detection spans three complementary analytical paradigms, each trading off precision, generalization, and interpretability:"))
    body.append(bullet("Network Flow Telemetry vs. Packet Inspection", "Deep Packet Inspection (DPI) examines full packet payloads but struggles with pervasive TLS encryption and high-throughput line rates. Flow telemetry (such as NetFlow, IPFIX, Zeek logs, and CICFlowMeter CSV exports) aggregates packet headers, inter-arrival times, TCP flags, and directional byte distributions per bidirectional session, enabling sub-millisecond statistical inference without inspecting encrypted payloads."))
    body.append(bullet("Signature-Based Detection", "Rule engines evaluate packet or flow attributes against curated Indicators of Compromise (IoCs) and protocol heuristics. They provide immediate human-readable attribution and near-zero false alarms, but zero generalization beyond authored signatures."))
    body.append(bullet("Supervised Machine Learning (Random Forest)", "Random Forest (Breiman, 2001) constructs an ensemble of decorrelated decision trees via bootstrap sampling and random feature subspacing at each split. In tabular cybersecurity benchmarks, tree ensembles resist non-linear feature scaling sensitivity, tolerate skewed distributions, and output calibrated class posterior probabilities."))
    body.append(bullet("Semi-Supervised Anomaly Detection (Isolation Forest)", "Isolation Forest (Liu, Ting, & Zhou, 2008) isolates outliers using randomized binary partitions rather than expensive distance or density estimation. Because anomalous flows are sparse and structurally distinct, they terminate at shorter average tree depths, yielding continuous anomaly scores without requiring labeled attack samples during training."))
    body.append(bullet("Explainable AI (SHAP TreeExplainer)", "Rooted in cooperative game theory, Shapley Additive exPlanations (Lundberg & Lee, 2017; Lundberg et al., 2020) assign each input feature an exact additive contribution toward a specific tree-ensemble class probability. Pairing supervised SHAP attributions with feature-wise baseline z-scores gives analysts transparent evidence regardless of which engine raised the alert."))
    body.append(body_p("Following this layered design, the implemented project separates offline training and validation calibration from runtime inference. Input telemetry is schema-validated before scaling, evaluated in parallel by both ensembles, routed through a swappable decision policy into grouped incidents, and surfaced in an analyst-facing Streamlit dashboard protected by cryptographic model verification."))

    # ---- Related Works / Existing System ----
    body.append(heading("Related Works / Existing System", level=1))
    body.append(body_p("Prior literature on machine learning-based NIDS establishes both the strength of tree ensembles on tabular flow datasets and major methodological pitfalls in public benchmark evaluations:"))
    body.append(bullet("CIC-IDS2017 Benchmark Creation", "Sharafaldin, Lashkari, and Ghorbani (2018) introduced CIC-IDS2017 across five capture days combining realistic benign background traffic with DoS, DDoS, Brute Force, Botnet, PortScan, Web Attack, and Infiltration scenarios extracted into 78+ CICFlowMeter features."))
    body.append(bullet("Comparative ML/DL NIDS Studies", "Ahmad et al. (2021) systematically reviewed machine learning and deep learning NIDS designs, noting high benchmark accuracy alongside recurring overfitting and false-alarm challenges. Sarhan et al. (2021) evaluated multiple classifiers across standardized NetFlow feature sets and found tree-based ensembles consistently outperformed heavier neural baselines in F1-score and inference speed."))
    body.append(bullet("CIC-IDS2017 Data Quality Audits", "Engelen, Rimmer, and Joosen (2021) uncovered duplicate records, infinite rate values, and feature-extraction artifacts in CIC-IDS2017 that inflate naive cross-validation metrics. Rosay, Carlier, and Leroux (2022) and Lanvin, Sommer, and Cavalli (2023) similarly documented dataset labeling errors and missing-flow anomalies, underscoring the necessity of rigorous deduplication and leakage-free splitting."))
    body.append(bullet("Tree Ensembles, Isolation, and Explainability", "Breiman (2001) formalized Random Forests, Liu et al. (2008) introduced Isolation Forest for linear-time anomaly isolation, and Lundberg and Lee (2017) with Lundberg et al. (2020) enabled exact TreeExplainer attributions for ensemble models."))

    body.append(make_p([("Table 1: Comparison of intrusion detection paradigms and the proposed hybrid system.", True, True)], sz_hp=20, align="left", before=60, after=40, line=230, keep_next=True, color="334155"))
    body.append(make_table(
        ["Detection Paradigm", "Known Attacks", "Unseen Patterns", "False Alarm Rate", "Analyst Explainability"],
        [
            ["Signature-Based (Snort / Suricata)", "Very High (Rule Match)", "Zero (No Rule)", "Very Low (< 0.1%)", "High (Explicit Rule)"],
            ["Supervised ML Only (Random Forest)", "Very High (> 99% Recall)", "Very Low (Closed-World)", "Low (0.26% in Test)", "Opaque Without XAI"],
            ["Anomaly-Only (Isolation Forest)", "Moderate (Unlabeled)", "Moderate (Outlier Depth)", "High (5%–15% Typical)", "Low (Single Score Only)"],
            ["Proposed Hybrid System (RF + IF)", "Very High (99.94% Recall)", "Selective (86.1% Infiltration)", "Managed (3.21% Tiered FPR)", "High (SHAP + Z-Scores)"],
        ],
        [2400, 1750, 1850, 1700, 1660],
        aligns=["left", "center", "center", "center", "left"],
    ))
    body.append(body_p("Research Gap: Existing studies frequently evaluate supervised classifiers on un-deduplicated splits without withholding entire attack families, rarely quantify the exact false-positive surge caused by adding unsupervised anomaly detection, and seldom integrate policy-driven severity tiering, alert grouping, and dual-mode XAI into one reproducible system. This project directly targets that operational gap.", after=80))

    # ---- Detailed Problem Statement ----
    body.append(heading("Detailed Problem Statement", level=1))
    body.append(body_p("Bridging the divide between academic intrusion detection benchmarks and practical Security Operations Center triage requires addressing four concrete gaps between current systems and the desired architecture:", after=65))
    body.append(bullet("Current State", "Signature engines cannot flag novel traffic profiles; standalone supervised models such as Random Forest fail silently on unmodeled threats (predicting 36 of 36 CIC-IDS2017 Infiltration flows as BENIGN); standalone anomaly detectors flood queues with spurious alerts; and raw model outputs lack actionable justification or deduplicated incident views."))
    body.append(bullet("Desired Future State", "An integrated, reproducible NIDS pipeline that preserves near-perfect known-attack classification, surfaces anomalous departures from benign behavior, separates deep anomalies from marginal edge noise through configurable severity policies, consolidates repetitive flow alerts into incidents, and explains each alert with feature-level evidence."))
    body.append(bullet("Identified Gaps Addressed", "(1) Eliminating train/test leakage via duplicate removal, socket-identifier exclusion, and validation-only threshold selection; (2) Mitigating the 9.42% baseline hybrid false-positive rate using a Tiered Severity Policy (cutting actionable FPR to 3.21%); (3) Providing both SHAP attributions (for supervised verdicts) and training-baseline z-scores (for anomaly-only alerts); and (4) Protecting serialized models via SHA-256 verification before deserialization."))

    # ---- Methods / Algorithms ----
    body.append(heading("Methods/Algorithms", level=1))
    body.append(body_p("Figure 1 illustrates the end-to-end architecture reconstructed directly from the implemented Python modules in src/ and dashboard/."))
    body.extend(make_figure("rId12", FIG_DIR / "fig_system_architecture.png", 6.2, "Figure 1: Reconstructed offline training and runtime hybrid detection architecture.", 10))

    body.append(heading("1. Dataset Audit and Preprocessing (src/audit_dataset.py, src/preprocess.py)", level=2))
    body.append(body_p("All eight raw CSV files in data/raw/MachineLearningCVE/ (844 MB total) were audited non-destructively and cleaned via chunked ingestion (100,000 rows per chunk, cp1252 encoding). Table 2 summarizes the raw corpus composition."))
    body.append(make_p([("Table 2: Raw CIC-IDS2017 capture corpus audited across all eight CSV files.", True, True)], sz_hp=20, align="left", before=40, after=40, line=230, keep_next=True, color="334155"))
    body.append(make_table(
        ["Raw Capture File", "Raw Rows", "Missing / Inf", "Traffic Categories"],
        [
            ["Monday-WorkingHours.pcap_ISCX.csv", "529,918", "64 / 810", "BENIGN (100%)"],
            ["Tuesday-WorkingHours.pcap_ISCX.csv", "445,909", "201 / 327", "BENIGN, FTP-Patator, SSH-Patator"],
            ["Wednesday-workingHours.pcap_ISCX.csv", "692,703", "1,008 / 1,586", "BENIGN, DoS (Hulk, GoldenEye, slowloris, Slowhttptest), Heartbleed"],
            ["Thursday-Morning-WebAttacks.pcap_ISCX.csv", "170,366", "20 / 250", "BENIGN, Web Attack (Brute Force, XSS, Sql Injection) [Withheld]"],
            ["Thursday-Afternoon-Infilteration.pcap_ISCX.csv", "288,602", "18 / 396", "BENIGN, Infiltration (36 flows) [Withheld]"],
            ["Friday-WorkingHours-Morning.pcap_ISCX.csv", "191,033", "28 / 216", "BENIGN, Bot (1,966 flows)"],
            ["Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "286,467", "15 / 727", "BENIGN, PortScan (158,930 flows)"],
            ["Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "225,745", "4 / 64", "BENIGN, DDoS (128,027 flows)"],
            ["Total Raw Corpus", "2,830,743", "1,358 / 4,376", "14 Attack Categories + BENIGN"],
        ],
        [3360, 1200, 1300, 3500],
        aligns=["left", "right", "center", "left"],
    ))
    body.append(body_p("Preprocessing strips header whitespace, replaces 4,376 infinite rate values and 1,358 missing cells with 0, drops 308,381 exact duplicate rows, and removes socket identifiers (DROP_COLS) if present. From the 2,522,362 unique flows, 2,179 flows belonging to Infiltration (36) and the three Web Attack classes (1,470 Brute Force; 652 XSS; 21 SQL Injection) are isolated into data/processed/withheld.parquet. The remaining 2,520,183 known-category flows undergo a stratified 60/20/20 split (random_state=42) into train.parquet (1,512,109 rows), val.parquet (504,037 rows), and test.parquet (504,037 rows)."))

    body.append(heading("2. Feature Schema, Validation, and Cryptographic Gate", level=2))
    body.append(body_p("Exactly 78 numeric flow features (data/processed/features.json) are enforced at runtime by InputValidator (src/validator.py), which caps interactive batches at 50,000 rows and 50 MB, coerces unexpected non-numeric text, sanitizes NaN and ±Inf values to 0.0, and casts arrays to float32. Prior to deserializing any scikit-learn pickle artifact, src/security.py validates SHA-256 digests against models/manifest.json via constant-time hmac.compare_digest (and optional Ed25519 signature verification via src/signing.py when IDS_MANIFEST_PUBKEY is configured)."))

    body.append(heading("3. Supervised Random Forest & Semi-Supervised Isolation Forest", level=2))
    body.append(bullet("Random Forest (src/train_rf.py)", "StandardScaler is fit strictly on train.parquet and saved to models/rf_scaler.pkl. A 200-tree RandomForestClassifier (max_depth=None, class_weight='balanced', random_state=42) is trained across the 11 known classes (codes 0–8, 10, 11). On val.parquet (504,037 rows), it recorded Macro Precision 0.9371, Macro Recall 0.9961, Macro F1 0.9530, and binary FPR 0.0026."))
    body.append(bullet("Isolation Forest (src/train_iforest.py)", "A 200-tree IsolationForest (contamination=0.05, random_state=42) is fit exclusively on 1,257,890 BENIGN training flows after scaling. To prevent test leakage, the operating threshold t = 0.061102 is selected on val.parquet by sweeping 40 linearly spaced percentiles (1%–20%) for maximum binary F1 (yielding validation Precision 0.5621, Recall 0.5872, F1 0.5744)."))

    body.append(heading("4. Hybrid Decision Policies, Explainability, and Alert Triage", level=2))
    body.append(body_p("HybridDetector (src/hybrid.py) runs a single vectorized pass of rf.predict_proba() and iforest.decision_function(), then applies one of four swappable arbitration policies in src/policy.py (Table 3)."))
    body.append(make_p([("Table 3: Implemented hybrid arbitration policies and severity mappings (src/policy.py).", True, True)], sz_hp=20, align="left", before=40, after=40, line=230, keep_next=True, color="334155"))
    body.append(make_table(
        ["Policy Key", "Arbitration Rule (When RF Predicts BENIGN)", "Severity Tiers", "Operational Purpose"],
        [
            ["tiered (Default)", "score < -0.03 -> MEDIUM; -0.03 <= score < 0.0611 -> LOW; >= 0.0611 -> INFO", "HIGH, MEDIUM, LOW, INFO", "Separates deep anomalies from marginal noise"],
            ["baseline", "score < 0.061102 -> Anomaly (MEDIUM); else INFO", "HIGH, MEDIUM, INFO", "Maximum recall; high false-alarm volume"],
            ["balanced", "score < 0.0 -> Anomaly (MEDIUM); else INFO", "HIGH, MEDIUM, INFO", "Single-knob FPR reduction"],
            ["confidence_gated", "Suppresses marginal anomalies (>= -0.05) if P(BENIGN) >= 0.999", "HIGH, MEDIUM, INFO", "Experimental confidence-gated filtering"],
        ],
        [1650, 3450, 1750, 2510],
        aligns=["left", "left", "center", "left"],
    ))
    body.append(bullet("Explainable AI (src/explain.py)", "For classifier alerts, shap.TreeExplainer(rf) computes top-15 signed local Shapley attributions mapped accurately via rf.classes_ positions (handling withheld-class code gaps). Because SHAP explains the classifier rather than the anomaly detector, anomaly-only alerts default to baseline_deviation(), which ranks features by z-score distance from training mean and standard deviation."))
    body.append(bullet("Alert Grouping (src/alert_grouper.py)", "Non-INFO flows are grouped by (final_label, severity) and optional IP columns using 60-second tumbling windows when Timestamp is present, or bounded sequential index gaps (max gap 50, max group 1,000). Groups smaller than min_alerts (default 5) remain individual alerts in summarize_groups()."))
    body.append(bullet("Streamlit SOC Console (dashboard/app.py)", "A 6-page dark-theme console (Overview, Scan flows, Incidents, Investigate flow, Alert history, Detector health) enables live policy switching, sample/CSV scanning, SHAP and z-score inspection, anomaly-score ruler visualization, and optional SQLite alert verdicts without external network requests."))

    body.append(heading("5. Evaluation Metrics", level=2))
    body.append(body_p("In src/evaluate_hybrid.py, models are evaluated via Precision = TP / (TP + FP), Recall = TP / (TP + FN), F1 = 2 * Precision * Recall / (Precision + Recall), False Positive Rate (FPR) = FP / (FP + TN), actionable alert counts (HIGH + MEDIUM), and per-label detection rates on the 2,179 withheld records."))

    # ---- Expected Results ----
    body.append(heading("Expected Results", level=1, page_break=True))
    body.append(body_p("While full runtime test re-verification and standardized latency benchmarking remain scheduled for the final phase, empirical evaluation outputs already recorded in reports/eval_results.json establish clear quantitative baselines and trade-offs."))
    body.append(heading("1. Verified Interim Test Results (N = 504,037 Known-Split Flows)", level=2))
    body.append(make_p([("Table 4: Held-out known-attack test metrics across RF-only baseline and hybrid policies.", True, True)], sz_hp=20, align="left", before=40, after=40, line=230, keep_next=True, color="334155"))
    body.append(make_table(
        ["Pipeline / Policy", "Actionable Precision", "Actionable Recall", "Actionable FPR", "Actionable Alerts", "LOW Queue"],
        [
            ["RF-Only Baseline", "98.75%", "99.94%", "0.26%", "85,762", "0"],
            ["Hybrid — Tiered (Recommended)", "86.30%", "99.94%", "3.21%", "98,130", "26,042"],
            ["Hybrid — Balanced (t = 0.0)", "79.57%", "99.94%", "5.19%", "106,433", "0"],
            ["Hybrid — Confidence-Gated (Beta)", "86.02%", "99.95%", "3.28%", "98,459", "0"],
            ["Hybrid — Baseline (t = 0.0611)", "68.21%", "99.95%", "9.42%", "124,172", "0"],
        ],
        [2760, 1400, 1300, 1300, 1400, 1200],
        aligns=["left", "center", "center", "center", "right", "right"],
    ))
    body.extend(make_figure("rId13", FIG_DIR / "fig_policy_tradeoff.png", 6.2, "Figure 2: Precision, recall, and false-positive trade-offs across RF-only and hybrid policies.", 11))

    body.append(body_p("As shown in Table 4 and Figure 2, adding Isolation Forest under the Baseline policy raises known-attack recall slightly (99.94% to 99.95%) at the cost of surging FPR from 0.26% to 9.42% (38,410 anomaly alerts). Tiered Severity arbitration isolates 26,042 marginal flows into a LOW hunting queue, restoring actionable precision to 86.30% and reducing actionable FPR to 3.21%."))

    body.append(heading("2. Controlled Unseen-Category Results (N = 2,179 Withheld Flows)", level=2))
    body.append(make_p([("Table 5: Detection performance on attack categories withheld from supervised RF training.", True, True)], sz_hp=20, align="left", before=40, after=40, line=230, keep_next=True, color="334155"))
    body.append(make_table(
        ["Withheld Category", "Flows", "RF Alone", "IF Alone (t=0.0611)", "Hybrid Baseline", "Tiered Actionable (HIGH+MED)"],
        [
            ["Infiltration", "36", "0 (0.00%)", "31 (86.11%)", "31 (86.11%)", "24 (66.67%) [+7 LOW]"],
            ["Web Attack – Brute Force", "1,470", "69 (4.69%)", "74 (5.03%)", "143 (9.73%)", "140 (9.52%)"],
            ["Web Attack – XSS", "652", "21 (3.22%)", "18 (2.76%)", "39 (5.98%)", "37 (5.67%)"],
            ["Web Attack – Sql Injection", "21", "4 (19.05%)", "0 (0.00%)", "4 (19.05%)", "4 (19.05%)"],
            ["Total Withheld Corpus", "2,179", "94 (4.31%)", "123 (5.64%)", "217 (9.96%)", "205 (9.41%)"],
        ],
        [2360, 800, 1350, 1550, 1500, 1800],
        aligns=["left", "right", "center", "center", "center", "center"],
    ))
    body.extend(make_figure("rId14", FIG_DIR / "fig_withheld_detection.png", 6.1, "Figure 3: Detection coverage across the four withheld attack categories.", 12))

    body.append(body_p("In the withheld experiment, Random Forest missed 100% of Infiltration flows (0/36), whereas Isolation Forest flagged 31/36 (86.11%) under the validation threshold (24 MEDIUM and 7 LOW under Tiered). Conversely, HTTP-layer Web Attacks were flagged at only 5.98%–19.05% because their packet sizes and timing closely resemble normal web browsing. Importantly, this controlled experiment measures sensitivity to withheld CIC-IDS2017 categories and does not constitute proof of general zero-day detection in live networks."))

    body.append(heading("3. Final-Phase Verification Targets and Limitations", level=2))
    body.append(bullet("Environment and Automated QA", "During this audit, SHA-256 verification (src/security.py, 4/4 artifacts) and Ruff linting passed, while live pytest and Streamlit AppTest execution were blocked by a host Python 3.14.4 versus virtualenv Python 3.12 mismatch. Restoring the runtime environment and running all eight test suites are immediate next-phase priorities."))
    body.append(bullet("Benchmarking and Split Caveats", "Persisting full binary/multiclass confusion matrices, building a reproducible warm-up latency benchmark (resolving differing doc figures), and documenting the stratified random-split limitation (shared capture days across splits) will complete the final evaluation before viva."))

    # ---- References ----
    body.append(heading("References", level=1))
    refs = [
        "Ahmad, Z., Shahid Khan, A., Che Wai Shiang, C., Abdullah, J., & Ahmad, F. (2021). Network intrusion detection system: A systematic study of machine learning and deep learning approaches. Transactions on Emerging Telecommunications Technologies, 32(1), e4150.",
        "Breiman, L. (2001). Random Forests. Machine Learning, 45(1), 5–32.",
        "Engelen, G., Rimmer, V., & Joosen, W. (2021). Troubleshooting an incomplete machine learning anomaly detection pipeline: A case study on CIC-IDS2017. In Proceedings of the 2021 ACM Workshop on Artificial Intelligence and Security (AISEC '21), 25–35.",
        "Lanvin, N., Sommer, R., & Cavalli, A. (2023). Errors in the CICIDS2017 dataset and their impact on ML-based network intrusion detection. IEEE Transactions on Network and Service Management, 20(3), 2874–2888.",
        "Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. In 2008 Eighth IEEE International Conference on Data Mining (ICDM), 413–422.",
        "Lundberg, S. M., & Lee, S. I. (2017). A unified approach to interpreting model predictions. In Advances in Neural Information Processing Systems 30 (NeurIPS 2017), 4765–4774.",
        "Lundberg, S. M., Erion, G., Chen, H., DeGrave, A., Prutkin, J. M., Nair, B., Katz, R., Himmelfarb, J., Bansal, N., & Lee, S. I. (2020). From local explanations to global understanding with explainable AI for trees. Nature Machine Intelligence, 2(1), 56–67.",
        "Rosay, A., Carlier, F., & Leroux, B. (2022). Improving CIC-IDS-2017 with new missing flows and realistic evaluation. In 2022 IEEE 47th Conference on Local Computer Networks (LCN), 345–352.",
        "Sarhan, M., Layeghy, S., & Portmann, M. (2021). Evaluating machine learning algorithms for network intrusion detection using standard data sets. IEEE Access, 9, 87638–87654.",
        "Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. In Proceedings of ICISSP 2018, 108–116.",
    ]
    for idx, ref in enumerate(refs, 1):
        body.append(make_p(f"[{idx}]  {ref}", sz_hp=20, align="both", before=0, after=55, line=235, indent_left=360, hanging=360))

    # ---- AI Usage Disclosure & Sign-Off ----
    body.append(heading("AI Tool Usage Disclosure", level=2))
    body.append(body_p("In accordance with MCA Case Study (25CSA698A) guidelines, AI assistance was used strictly as a supporting tool for repository verification, architectural diagram formatting, debugging analysis, and academic language refinement within the 20% usage limit. All experimental pipelines, dataset decisions, model configurations, evaluations, and conclusions were independently reviewed and verified against project code and outputs by the student.", after=140, sz_hp=21))
    body.append(sign_tbl)

    # Link footer in sectPr
    ftr_ref = ET.Element(w_tag("footerReference"))
    ftr_ref.set(w_tag("type"), "default")
    ftr_ref.set(f"{{{R_NS}}}id", "rId15")
    sect_pr.insert(0, ftr_ref)
    body.append(sect_pr)

    # Strip undeclared prefixes from mc:Ignorable so LibreOffice/Word XML parsers never choke
    mc_ign = "{http://schemas.openxmlformats.org/markup-compatibility/2006}Ignorable"
    if mc_ign in root.attrib:
        root.attrib[mc_ign] = "w14 wp14"

    # Update relationships & content types without altering default XML namespaces
    rels_str = rels_bytes.decode("utf-8")
    new_rels_xml = (
        '<Relationship Id="rId12" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/fig_system_architecture.png"/>'
        '<Relationship Id="rId13" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/fig_policy_tradeoff.png"/>'
        '<Relationship Id="rId14" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/fig_withheld_detection.png"/>'
        '<Relationship Id="rId15" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
    )
    rels_str = rels_str.replace("</Relationships>", new_rels_xml + "</Relationships>")

    ct_str = ct_bytes.decode("utf-8")
    ct_str = ct_str.replace(
        "</Types>",
        '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>',
    )

    files["word/document.xml"] = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    files["word/_rels/document.xml.rels"] = rels_str.encode("utf-8")
    files["[Content_Types].xml"] = ct_str.encode("utf-8")
    if "docProps/core.xml" in files:
        files["docProps/core.xml"] = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<dc:title>Network Intrusion Detection System (IDS) - Interim Report</dc:title>'
            '<dc:subject>Case Study 25CSA698A</dc:subject>'
            '<dc:creator>Anandhu S Nair</dc:creator>'
            '<cp:lastModifiedBy>Anandhu S Nair</cp:lastModifiedBy>'
            '</cp:coreProperties>'
        ).encode("utf-8")
    files["word/footer1.xml"] = build_footer_xml()
    files["word/media/fig_system_architecture.png"] = (FIG_DIR / "fig_system_architecture.png").read_bytes()
    files["word/media/fig_policy_tradeoff.png"] = (FIG_DIR / "fig_policy_tradeoff.png").read_bytes()
    files["word/media/fig_withheld_detection.png"] = (FIG_DIR / "fig_withheld_detection.png").read_bytes()

    with zipfile.ZipFile(OUT_DOCX, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)
    print(f"Wrote DOCX: {OUT_DOCX} ({OUT_DOCX.stat().st_size:,} bytes)")

    subprocess.run(
        ["libreoffice", "--headless", "--convert-to", "pdf", "--outdir", str(SUBMISSION_DIR), str(OUT_DOCX)],
        check=True,
    )
    print(f"Wrote PDF:  {OUT_PDF} ({OUT_PDF.stat().st_size:,} bytes)")


if __name__ == "__main__":
    build_report()
