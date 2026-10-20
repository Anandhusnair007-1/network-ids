import os
from pathlib import Path
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, fill_hex):
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    cell._tc.get_or_add_tcPr().append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('w:top', top), ('w:bottom', bottom), ('w:left', left), ('w:right', right)]:
        node = OxmlElement(m)
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def style_table_header(row, col_widths, bg_hex="1A365D", text_color="FFFFFF"):
    for i, cell in enumerate(row.cells):
        set_cell_background(cell, bg_hex)
        set_cell_margins(cell, top=120, bottom=120, left=140, right=140)
        cell.width = col_widths[i]
        for p in cell.paragraphs:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            for r in p.runs:
                r.font.bold = True
                r.font.name = 'Arial'
                r.font.size = Pt(9.5)
                r.font.color.rgb = RGBColor.from_string(text_color)

def style_table_row(row, col_widths, bg_hex="FFFFFF", text_aligns=None):
    for i, cell in enumerate(row.cells):
        if bg_hex != "FFFFFF":
            set_cell_background(cell, bg_hex)
        set_cell_margins(cell, top=90, bottom=90, left=140, right=140)
        cell.width = col_widths[i]
        align = text_aligns[i] if text_aligns else WD_ALIGN_PARAGRAPH.LEFT
        for p in cell.paragraphs:
            p.alignment = align
            for r in p.runs:
                r.font.name = 'Arial'
                r.font.size = Pt(9)
                r.font.color.rgb = RGBColor(0x2D, 0x37, 0x48)

def add_callout(doc, text, title=None):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    set_cell_background(cell, "EDF2F7")
    set_cell_margins(cell, top=140, bottom=140, left=200, right=160)
    
    # Left border
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(f'''
        <w:tcBorders {nsdecls("w")}>
            <w:left w:val="single" w:sz="24" w:space="0" w:color="2B6CB0"/>
            <w:top w:val="none"/>
            <w:right w:val="none"/>
            <w:bottom w:val="none"/>
        </w:tcBorders>
    ''')
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    if title:
        rt = p.add_run(f"{title}: ")
        rt.bold = True
        rt.font.name = 'Arial'
        rt.font.size = Pt(10)
        rt.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D)
    
    r = p.add_run(text)
    r.font.name = 'Arial'
    r.font.size = Pt(9.5)
    r.font.italic = True
    r.font.color.rgb = RGBColor(0x2D, 0x37, 0x48)
    
    p_after = doc.add_paragraph()
    p_after.paragraph_format.space_after = Pt(6)

def build_docx(filename="reports/Network_IDS_Project_Report_Anandhu_S_Nair.docx"):
    doc = Document()
    
    # Page setup - Margins 1 inch
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)
    
    # Configure base styles
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Arial'
    normal_style.font.size = Pt(10.5)
    normal_style.font.color.rgb = RGBColor(0x2D, 0x37, 0x48)
    normal_style.paragraph_format.line_spacing = 1.18
    normal_style.paragraph_format.space_after = Pt(6)

    # ---------------------------------------------------------
    # 1. TITLE PAGE
    # ---------------------------------------------------------
    p_inst = doc.add_paragraph()
    p_inst.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_inst.paragraph_format.space_before = Pt(20)
    p_inst.paragraph_format.space_after = Pt(4)
    r_inst = p_inst.add_run("AMRITA VISHWA VIDYAPEETHAM\nAMRITA AHEAD ONLINE")
    r_inst.font.name = 'Arial'
    r_inst.font.size = Pt(14)
    r_inst.font.bold = True
    r_inst.font.color.rgb = RGBColor(0x74, 0x1B, 0x24) # Amrita Maroon

    p_prog = doc.add_paragraph()
    p_prog.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_prog.paragraph_format.space_after = Pt(36)
    r_prog = p_prog.add_run("DEPARTMENT OF COMPUTER SCIENCE & APPLICATIONS\nMaster of Computer Applications (MCA) — Regular, Semester 3\nMinor Project (21CSA391A)")
    r_prog.font.name = 'Arial'
    r_prog.font.size = Pt(11)
    r_prog.font.color.rgb = RGBColor(0x4A, 0x55, 0x68)

    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_after = Pt(18)
    r_title = p_title.add_run("DESIGN, IMPLEMENTATION, AND EVALUATION OF A HYBRID MACHINE-LEARNING NETWORK INTRUSION DETECTION SYSTEM WITH WITHHELD-CATEGORY ANOMALY DETECTION AND EXPLAINABLE ALERT TRIAGE")
    r_title.font.name = 'Arial'
    r_title.font.size = Pt(17)
    r_title.font.bold = True
    r_title.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D)

    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_after = Pt(48)
    r_sub = p_sub.add_run("A Technical Minor Project Report Submitted in Partial Fulfillment of the Requirements for the Degree of Master of Computer Applications")
    r_sub.font.name = 'Arial'
    r_sub.font.size = Pt(10.5)
    r_sub.font.italic = True
    r_sub.font.color.rgb = RGBColor(0x71, 0x80, 0x96)

    # Student metadata table
    tbl_meta = doc.add_table(rows=4, cols=2)
    tbl_meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_data = [
        ("Candidate Name:", "Anandhu S Nair"),
        ("Roll Number:", "AA.SC.P2MCA25070089"),
        ("Academic Program:", "Master of Computer Applications (MCA)"),
        ("Evaluation Dataset:", "CIC-IDS2017 (Canadian Institute for Cybersecurity)")
    ]
    col_w = [Inches(2.5), Inches(3.8)]
    for idx, (label, val) in enumerate(meta_data):
        row = tbl_meta.rows[idx]
        row.cells[0].paragraphs[0].text = label
        row.cells[0].paragraphs[0].runs[0].font.bold = True
        row.cells[1].paragraphs[0].text = val
        style_table_row(row, col_w, "FFFFFF")
    
    p_date = doc.add_paragraph()
    p_date.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_date.paragraph_format.space_before = Pt(40)
    r_date = p_date.add_run("Academic Year 2025–2026")
    r_date.font.size = Pt(11)
    r_date.font.bold = True
    r_date.font.color.rgb = RGBColor(0x4A, 0x55, 0x68)

    doc.add_page_break()

    # Helper function for adding headings
    def add_h1(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(18)
        p.paragraph_format.space_after = Pt(8)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.font.name = 'Arial'
        r.font.size = Pt(14)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D) # Navy
        return p

    def add_h2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.font.name = 'Arial'
        r.font.size = Pt(12)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0x2B, 0x6C, 0xB0) # Blue
        return p

    def add_h3(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.font.name = 'Arial'
        r.font.size = Pt(10.5)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0x2D, 0x37, 0x48)
        return p

    # ---------------------------------------------------------
    # 2. ABSTRACT & KEYWORDS
    # ---------------------------------------------------------
    add_h1("2. Abstract & Keywords")
    
    p = doc.add_paragraph()
    p.add_run(
        "Modern enterprise computer networks face continuous threats from sophisticated cyberattacks, including volumetric denial-of-service, "
        "lateral infiltration, and brute-force intrusions. Traditional Signature-based Network Intrusion Detection Systems (NIDS) fail to identify "
        "novel attack vectors, while purely supervised machine learning models demonstrate high accuracy only on threat categories explicitly "
        "represented in training data. This technical project designs, implements, and rigorously evaluates a dual-engine Hybrid Network Intrusion "
        "Detection System that combines a supervised Random Forest multiclass classifier (200 estimators) with an unsupervised Isolation Forest "
        "anomaly detector, developed upon the benchmark CIC-IDS2017 dataset (2,830,743 raw network flows; 2,522,362 deduplicated flows)."
    )

    p = doc.add_paragraph()
    p.add_run(
        "To rigorously examine whether unsupervised anomaly detection can bridge the zero-day visibility gap, a controlled withheld-category "
        "experiment was executed: four attack categories—Infiltration, Web Attack Brute Force, Web Attack XSS, and Web Attack SQL Injection (N = 2,179 flows)—"
        "were entirely withheld from supervised training and reserved solely for evaluation. The Isolation Forest was trained strictly on benign traffic, "
        "and its decision threshold (t = 0.061102) was calibrated exclusively on a validation split to eliminate data leakage. The hybrid system incorporates "
        "SHAP (Shapley Additive exPlanations) TreeExplainer for per-flow feature attribution and a sliding-window Alert Grouper to mitigate Security Operations "
        "Center (SOC) alert fatigue, wrapped in an interactive 5-page Streamlit security dashboard."
    )

    p = doc.add_paragraph()
    p.add_run(
        "Empirical evaluation on a test split of 504,037 network flows demonstrates that the supervised Random Forest attains near-optimal performance on known "
        "attacks (Macro-F1 = 0.9345, Binary Recall = 99.94%, Binary Precision = 98.75%, False Positive Rate = 0.26%). In the withheld-category experiment, "
        "the Random Forest was completely blind to Infiltration attacks (0.0% detection; 36/36 classified as BENIGN), whereas the Isolation Forest successfully "
        "flagged 31 of 36 Infiltration flows (86.11% detection rate). However, on HTTP-layer web attacks, the Isolation Forest detected only 5.03% of Brute Force, "
        "2.76% of XSS, and 0.0% of SQL Injection flows, establishing that statistical transport/network flow features cannot discern malicious payloads without "
        "deep application-layer inspection. Furthermore, incorporating the anomaly detector into the hybrid pipeline caused the overall false positive rate to surge "
        "from 0.26% to 9.42% on the test split, generating 38,405 additional false alerts. To counteract this operational burden, the Alert Grouper demonstrated a "
        "99.56% compression ratio in alert triage volume. Latency benchmarking revealed per-flow inference costs of 5.59 microseconds for Random Forest and 15.79 "
        "microseconds for the complete hybrid pipeline (~63,330 flows/sec). This project provides a transparent, reproducible assessment of hybrid machine learning "
        "in production network defense, delineating its tangible strengths and operational boundaries."
    )

    p_kw = doc.add_paragraph()
    r_kwt = p_kw.add_run("Keywords: ")
    r_kwt.bold = True
    p_kw.add_run("Network Intrusion Detection System (NIDS), Hybrid Machine Learning, Random Forest, Isolation Forest, CIC-IDS2017, Withheld-Category Experiment, SHAP Explainability, Alert Fatigue Mitigation, False Positive Trade-Off.")

    doc.add_page_break()

    # ---------------------------------------------------------
    # 3. INTRODUCTION & PROBLEM STATEMENT
    # ---------------------------------------------------------
    add_h1("3. Introduction & Problem Statement")
    
    add_h2("3.1 Context & Background")
    p = doc.add_paragraph()
    p.add_run(
        "Enterprise computer networks serve as the backbone for mission-critical digital services, financial transactions, and public infrastructure. "
        "Concurrently, the frequency, sophistication, and automated orchestration of network intrusions have escalated. Malicious actors leverage "
        "distributed denial-of-service (DDoS) botnets, automated credential brute-forcing, application vulnerability exploits, and multi-stage infiltration "
        "campaigns to compromise system confidentiality, integrity, and availability. Network Intrusion Detection Systems (NIDS) represent a primary "
        "perimeter defense layer tasked with inspecting packet streams or summarized flow records to identify unauthorized or anomalous behaviors."
    )

    add_h2("3.2 Problem Statement")
    p = doc.add_paragraph()
    p.add_run(
        "Commercial and open-source NIDS deployments predominantly rely on signature-matching engines (e.g., Snort, Suricata, Zeek). While deterministic "
        "signatures yield exceptionally low false positive rates and rapid execution for known threats, they suffer from fundamental architectural blindness: "
        "they cannot detect previously unseen attack variants, novel zero-day exploits, or obfuscated traffic patterns for which no rule has been authored. "
        "To overcome signature brittleness, academic research has extensively investigated supervised machine learning classifiers (e.g., Random Forests, "
        "Support Vector Machines, Deep Neural Networks). However, conventional supervised NIDS paradigms introduce three critical operational deficiencies:\n"
        "1. Closed-World Assumption: Supervised models assume that training data encapsulates all possible attack distributions. When confronted with "
        "an attack category withheld from training, the classifier erroneously maps the malicious flows into known training classes (most frequently misclassifying "
        "them as BENIGN), providing a false sense of security.\n"
        "2. Black-Box Opacity: High-capacity classifiers lack inherent transparency. Security analysts cannot easily decipher why a specific flow triggered an alert, "
        "impeding incident response and root-cause verification.\n"
        "3. Alert Fatigue and Anomaly Cost: Unsupervised anomaly detectors (e.g., Isolation Forests, One-Class SVMs) are theoretically capable of flagging "
        "unseen patterns. However, their sensitivity to benign network variance routinely triggers an unsustainable volume of false alarms, overwhelming SOC analysts."
    )

    # ---------------------------------------------------------
    # 4. MOTIVATION, OBJECTIVES & RESEARCH QUESTIONS
    # ---------------------------------------------------------
    add_h1("4. Motivation, Objectives & Research Questions")

    add_h2("4.1 Motivation")
    p = doc.add_paragraph()
    p.add_run(
        "Rather than treating supervised classification and unsupervised anomaly detection as competing paradigms, this project is motivated by their operational "
        "synergy. A supervised classifier provides high confidence, specific threat family labels, and negligible false alarms for known attack signatures. "
        "Conversely, an unsupervised anomaly detector acts as an independent safety net for traffic deviating from normal benign profiles. Combining both into a "
        "structured hybrid architecture with explainability and alert triage provides an empirically validated framework for realistic network defense."
    )

    add_h2("4.2 Main Objectives & Deliverables")
    p = doc.add_paragraph()
    p.add_run("The primary engineering and scientific deliverables of this project encompass:")
    bullet_items = [
        "Data Pipeline: Comprehensive audit, cleaning, infinite/NaN handling, deduplication, and leakage-resistant 60/20/20 stratified partitioning of the CIC-IDS2017 dataset.",
        "Withheld-Category Design: Isolation of specific attack families (Infiltration and Web Attacks) from supervised training to establish a controlled benchmark for novel attack detection.",
        "Dual-Engine Implementation: Production-grade implementation of a 200-tree Random Forest classifier and a benign-trained Isolation Forest anomaly detector with validation-tuned decision thresholds.",
        "Hybrid Triage Logic: Tiered severity classification (HIGH for known attacks, MEDIUM for unclassified anomalies, INFO for benign flows).",
        "Explainable AI: Integration of SHAP TreeExplainer for per-flow local feature attribution.",
        "Alert Grouping: Time-windowed aggregation engine to compress raw alert streams and combat SOC fatigue.",
        "Interactive SOC Dashboard: Development of a modular 5-page Streamlit application.",
        "Empirical Validation: Rigorous measurement of precision, recall, F1-scores, false positive rates, confusion matrices, alert volumes, and inference latencies."
    ]
    for bi in bullet_items:
        p_b = doc.add_paragraph(style='List Bullet')
        r_b = p_b.add_run(bi.split(":")[0] + ":")
        r_b.bold = True
        p_b.add_run(bi[len(bi.split(":")[0])+1:])

    add_h2("4.3 Formal Research Questions")
    p = doc.add_paragraph()
    p.add_run("This technical study evaluates four foundational research questions using empirical evidence:")
    rqs = [
        ("RQ1 (Supervised Fidelity)", "How effectively does the Random Forest classifier identify known attack categories represented in its training data across multiclass and binary metrics?"),
        ("RQ2 (Novel Category Detection)", "Can an unsupervised Isolation Forest trained strictly on benign traffic successfully flag attack categories withheld from supervised training?"),
        ("RQ3 (Hybrid Trade-Off & Cost)", "Does the hybrid architecture improve held-out attack detection compared to a classifier-only baseline, and what exact false-positive cost does it introduce?"),
        ("RQ4 (Operational Triage & Utility)", "How effectively do SHAP explanations and sliding-window alert grouping support alert investigation and mitigate analyst alert fatigue?")
    ]
    for code, q in rqs:
        p_rq = doc.add_paragraph()
        r_c = p_rq.add_run(f"{code}: ")
        r_c.bold = True
        r_c.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D)
        p_rq.add_run(q)

    # ---------------------------------------------------------
    # 5. BACKGROUND & LITERATURE REVIEW
    # ---------------------------------------------------------
    add_h1("5. Background & Literature Review")

    p = doc.add_paragraph()
    p.add_run(
        "Intrusion detection has evolved across four decades, transitioning from rule-based expert systems to statistical baselines, "
        "and recently to machine-learning and deep-learning architectures."
    )

    add_h2("5.1 Machine Learning in Intrusion Detection")
    p = doc.add_paragraph()
    p.add_run(
        "Supervised ensemble methods, particularly Random Forests (Breiman, 2001), have emerged as the premier tabular classification algorithm "
        "in cybersecurity benchmarks. By constructing an ensemble of decorrelated decision trees using bagging (bootstrap aggregation) and random "
        "feature subsets, Random Forests achieve high expressive capacity while minimizing overfitting variance. Ahmad et al. (2021) and Sarhan et al. (2021) "
        "benchmarked multiple machine learning paradigms across contemporary datasets, demonstrating that tree-based ensembles consistently outperform deep "
        "feedforward neural networks and support vector machines on tabular flow data in both F1-score and inference speed."
    )

    add_h2("5.2 Anomaly Detection & Isolation Forests")
    p = doc.add_paragraph()
    p.add_run(
        "Unsupervised anomaly detection operates under the premise that malicious events exhibit structural divergence from normal operational baselines. "
        "Isolation Forest (Liu, Ting, & Zhou, 2008) operates on a distinct, computationally efficient principle: rather than constructing profiles of normal "
        "clusters or estimating parametric density functions (such as Gaussian Mixture Models or Kernel Density Estimation), it explicitly isolates anomalies. "
        "Because anomalies are 'few and different,' they possess shorter average path lengths in randomized binary isolation trees (iTrees). An anomaly score "
        "is derived from the normalized expectation of tree depth across an ensemble of iTrees."
    )

    add_h2("5.3 Explainable AI (XAI) in Cybersecurity")
    p = doc.add_paragraph()
    p.add_run(
        "Deploying black-box machine learning in high-stakes operational security creates severe trust and verification deficits. When an IDS triggers an alert, "
        "security analysts must validate whether the flow is a genuine threat or benign noise. Lundberg & Lee (2017) formalized SHAP (Shapley Additive exPlanations), "
        "grounded in cooperative game theory, which assigns each feature an additive importance value representing its marginal contribution to the prediction. "
        "Lundberg et al. (2020) subsequently introduced TreeExplainer, enabling exact, polynomial-time calculation of Shapley values for tree ensembles, rendering "
        "per-flow explainability computationally viable for Random Forests."
    )

    # ---------------------------------------------------------
    # 6. EXISTING IDS APPROACHES & LIMITATIONS
    # ---------------------------------------------------------
    add_h1("6. Existing IDS Approaches & Limitations")

    p = doc.add_paragraph()
    p.add_run("To contextualize the contributions of this project, Table 1 synthesizes the operational characteristics of contemporary IDS paradigms.")

    tbl_comp = doc.add_table(rows=5, cols=5)
    tbl_comp.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Paradigm", "Known Attack Detection", "Novel Attack Detection", "FPR / False Alarms", "Explainability"]
    w_comp = [Inches(1.5), Inches(1.2), Inches(1.2), Inches(1.3), Inches(1.3)]
    for i, title in enumerate(headers):
        tbl_comp.rows[0].cells[i].paragraphs[0].text = title
    style_table_header(tbl_comp.rows[0], w_comp)

    rows_comp = [
        ("Signature-Based (Snort/Suricata)", "Very High (Deterministic)", "Zero (Blind to Unseen)", "Extremely Low (< 0.1%)", "High (Rule Definition)"),
        ("Supervised ML (RF/XGBoost)", "High to Very High (> 98%)", "Extremely Low (Closed-World)", "Low (0.2% - 1.0%)", "Opaque without XAI"),
        ("Anomaly-Only (One-Class/IF)", "Moderate (Unlabeled)", "Moderate (Flags Deviations)", "High (5% - 15%)", "Poor (Single Distance Metric)"),
        ("Proposed Hybrid System", "Very High (RF 99.9% Recall)", "Selective (Flags Structural Deviations)", "Controlled via Tiered Triage", "High (SHAP + Anomaly Evidence)")
    ]
    for r_idx, r_data in enumerate(rows_comp):
        row = tbl_comp.rows[r_idx + 1]
        for c_idx, val in enumerate(r_data):
            row.cells[c_idx].paragraphs[0].text = val
        bg = "F7FAFC" if r_idx % 2 == 1 else "FFFFFF"
        style_table_row(row, w_comp, bg)

    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_cap = p_cap.add_run("Table 1: Comparative matrix of network intrusion detection paradigms.")
    r_cap.font.size = Pt(8.5)
    r_cap.font.italic = True

    # ---------------------------------------------------------
    # 7. PROPOSED SYSTEM & ARCHITECTURE
    # ---------------------------------------------------------
    add_h1("7. Proposed System & Architecture")

    p = doc.add_paragraph()
    p.add_run(
        "The proposed system is structured as a modular, end-to-end analytical pipeline designed for deterministic execution, high throughput, "
        "and transparent operational investigation. Figure 1 illustrates the macro architecture of the system."
    )

    # Insert Fig 1
    if Path("reports/figures/fig1_system_architecture.png").exists():
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_picture("reports/figures/fig1_system_architecture.png", width=Inches(6.0))
        p_f1 = doc.add_paragraph()
        p_f1.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f1 = p_f1.add_run("Figure 1: End-to-end architectural dataflow of the Hybrid Network Intrusion Detection System.")
        r_f1.font.size = Pt(8.5)
        r_f1.font.italic = True

    p = doc.add_paragraph()
    p.add_run(
        "The pipeline processes network telemetry across five integrated stages:\n"
        "1. Ingestion & Preprocessing: Raw network flows are ingested, stripped of identifying socket metadata, cleaned of arithmetic anomalies, and scaled.\n"
        "2. Supervised Primary Engine: A 200-tree Random Forest computes multiclass attack probabilities.\n"
        "3. Unsupervised Secondary Engine: An Isolation Forest scores the flow against a benign structural baseline.\n"
        "4. Hybrid Decision Fusion: A deterministic logic engine evaluates both outputs to assign a final label and triage severity.\n"
        "5. Explainability & Triage Interface: High-severity events are explained via SHAP, aggregated by the Alert Grouper, and visualized on the Streamlit dashboard."
    )

    # ---------------------------------------------------------
    # 8. DATASET DESCRIPTION & DATA-QUALITY ANALYSIS
    # ---------------------------------------------------------
    add_h1("8. Dataset Description & Data-Quality Analysis")

    p = doc.add_paragraph()
    p.add_run(
        "The system was developed and benchmarked using the CIC-IDS2017 dataset, released by the Canadian Institute for Cybersecurity (Sharafaldin et al., 2018). "
        "Captured over five consecutive working days (Monday July 3, 2017 to Friday July 7, 2017) within a controlled emulation testbed, the dataset encompasses "
        "benign background traffic and a diverse spectrum of modern cyberattack scenarios."
    )

    add_h2("8.1 Raw File Audit & Discrepancies")
    p = doc.add_paragraph()
    p.add_run(
        "A rigorous initial audit of all 8 CSV files in the MachineLearningCVE distribution was executed using a specialized auditing script (audit_dataset.py). "
        "Table 2 records the empirical audit findings."
    )

    tbl_audit = doc.add_table(rows=9, cols=6)
    tbl_audit.alignment = WD_TABLE_ALIGNMENT.CENTER
    audit_headers = ["File / Day", "File Size", "Raw Rows", "Missing Cells", "Infinite Values", "Attack Categories Present"]
    w_aud = [Inches(1.8), Inches(0.8), Inches(0.9), Inches(0.8), Inches(0.8), Inches(1.4)]
    for i, title in enumerate(audit_headers):
        tbl_audit.rows[0].cells[i].paragraphs[0].text = title
    style_table_header(tbl_audit.rows[0], w_aud)

    audit_rows = [
        ("Monday-WorkingHours.csv", "168.7 MB", "529,918", "64", "810", "BENIGN (100%)"),
        ("Tuesday-WorkingHours.csv", "128.8 MB", "445,909", "201", "327", "FTP-Patator, SSH-Patator"),
        ("Wednesday-workingHours.csv", "214.7 MB", "692,703", "1,008", "1,586", "DoS Hulk, GoldenEye, slowloris, Slowhttptest, Heartbleed"),
        ("Thursday-Morning-WebAttacks.csv", "49.6 MB", "170,366", "20", "250", "Web Attack (Brute Force, XSS, Sql Injection)"),
        ("Thursday-Afternoon-Infilteration.csv", "79.3 MB", "288,602", "18", "396", "Infiltration (36 flows)"),
        ("Friday-Morning.csv", "55.6 MB", "191,033", "28", "216", "Bot (1,966 flows)"),
        ("Friday-Afternoon-PortScan.csv", "73.3 MB", "286,467", "15", "727", "PortScan (158,930 flows)"),
        ("Friday-Afternoon-DDos.csv", "73.6 MB", "225,745", "4", "64", "DDoS (128,027 flows)")
    ]
    for r_idx, r_data in enumerate(audit_rows):
        row = tbl_audit.rows[r_idx + 1]
        for c_idx, val in enumerate(r_data):
            row.cells[c_idx].paragraphs[0].text = val
        bg = "F7FAFC" if r_idx % 2 == 1 else "FFFFFF"
        style_table_row(row, w_aud, bg, [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.LEFT])

    p_cap2 = doc.add_paragraph()
    p_cap2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_cap2 = p_cap2.add_run("Table 2: Dataset audit across all 8 raw CSV files in CIC-IDS2017.")
    r_cap2.font.size = Pt(8.5)
    r_cap2.font.italic = True

    add_h2("8.2 Data Cleaning & Duplicate Removal")
    p = doc.add_paragraph()
    p.add_run(
        "Across the 2,830,743 raw records, the audit identified 1,358 missing cells and 4,376 infinite numeric values arising from zero-division in flow "
        "rate calculations (e.g., Flow Bytes/s and Flow Packets/s when Flow Duration equals zero). Furthermore, exact row deduplication revealed "
        "308,381 duplicate records (10.9% of the dataset). Allowing duplicate records to persist across random train/test splits leads to severe data "
        "leakage, artificially inflating classification accuracy. Post-deduplication, the clean corpus comprised 2,522,362 unique flow records."
    )

    # Insert Fig 2
    if Path("reports/figures/fig2_dataset_distribution.png").exists():
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_picture("reports/figures/fig2_dataset_distribution.png", width=Inches(5.8))
        p_f2 = doc.add_paragraph()
        p_f2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f2 = p_f2.add_run("Figure 2: Label distribution of the deduplicated CIC-IDS2017 dataset (logarithmic scale).")
        r_f2.font.size = Pt(8.5)
        r_f2.font.italic = True

    # ---------------------------------------------------------
    # 9. SYSTEM REQUIREMENTS & DEVELOPMENT ENVIRONMENT
    # ---------------------------------------------------------
    add_h1("9. System Requirements & Development Environment")

    p = doc.add_paragraph()
    p.add_run("The development, training, and benchmarking environment was standardized to guarantee strict reproducibility:")
    env_items = [
        ("Operating System", "Linux (Ubuntu 24.04 LTS / Debian-compatible x86_64 architecture)."),
        ("Programming Language", "Python 3.12.3 executing within an isolated virtual environment (.venv)."),
        ("Key Libraries", "scikit-learn 1.9.1, pandas 3.0.6, numpy 2.5.4, shap 0.54.1, streamlit 1.66.0, pyarrow 26.0.0, matplotlib 3.11.2, pytest 9.1.1."),
        ("Hardware Resources", "x86_64 multi-core processor (8 vCPUs utilized for parallel training via joblib n_jobs=-1), 16 GB system RAM."),
        ("Automation & Build", "Automated Makefile workflow managing auditing, preprocessing, model training, evaluation, testing, and dashboard serving.")
    ]
    for lbl, desc in env_items:
        p_e = doc.add_paragraph()
        r_el = p_e.add_run(f"• {lbl}: ")
        r_el.bold = True
        p_e.add_run(desc)

    # ---------------------------------------------------------
    # 10. METHODOLOGY & PREPROCESSING
    # ---------------------------------------------------------
    add_h1("10. Methodology & Preprocessing")

    add_h2("10.1 Feature Selection & Metadata Dropping")
    p = doc.add_paragraph()
    p.add_run(
        "To prevent trivial identity leakage and model overfitting to testbed topology, non-behavioral network identifiers were stripped before training. "
        "Specifically, Flow ID, Source IP, Destination IP, Source Port, and Timestamp were discarded. Retaining IP addresses or source ports would cause "
        "classifiers to memorize specific attacker/victim hosts rather than learning generalized flow dynamics. The remaining 78 numerical features represent "
        "statistical properties: forward/backward packet counts, inter-arrival times (IAT), packet length statistics, flag counts (SYN, FIN, RST, PSH, ACK), "
        "window advertisement sizes, and active/idle periods."
    )

    add_h2("10.2 Withheld Attack Category Isolation")
    p = doc.add_paragraph()
    p.add_run(
        "Before executing the training split, four attack categories were separated into a dedicated withheld evaluation partition:\n"
        "• Infiltration (N = 36 flows)\n"
        "• Web Attack – Brute Force (N = 1,470 flows)\n"
        "• Web Attack – XSS (N = 652 flows)\n"
        "• Web Attack – Sql Injection (N = 21 flows)\n"
        "Total withheld records: 2,179 flows. These rows were never seen by the Random Forest during training and were never used to tune anomaly thresholds."
    )

    add_h2("10.3 Leakage-Resistant Data Partitioning")
    p = doc.add_paragraph()
    p.add_run(
        "The remaining 2,520,183 known-category flows were partitioned into a 60 / 20 / 20 stratified split:\n"
        "• Training Split: 1,512,109 flows (1,257,890 BENIGN, 254,219 Known Attacks)\n"
        "• Validation Split: 504,037 flows (419,297 BENIGN, 84,740 Known Attacks)\n"
        "• Test Split: 504,037 flows (419,297 BENIGN, 84,740 Known Attacks)\n"
        "Feature scaling was performed using StandardScaler. The scaler was fit exclusively on the training split, and subsequently applied to transform "
        "the validation, test, and withheld partitions, eliminating data snooping."
    )

    # ---------------------------------------------------------
    # 11. MODEL DESIGN & HYBRID DECISION LOGIC
    # ---------------------------------------------------------
    add_h1("11. Model Design & Hybrid Decision Logic")

    add_h2("11.1 Supervised Random Forest Classifier")
    p = doc.add_paragraph()
    p.add_run(
        "The primary classifier is configured as a RandomForestClassifier with 200 estimators, unconstrained tree depth (max_depth=None), and balanced "
        "class weighting (class_weight='balanced') to counteract the 83:17 benign-to-attack imbalance. Gini impurity serves as the split criterion."
    )

    add_h2("11.2 Unsupervised Isolation Forest Anomaly Detector")
    p = doc.add_paragraph()
    p.add_run(
        "The Isolation Forest is trained exclusively on the 1,257,890 BENIGN records of the training split (contamination=0.05, 200 estimators). "
        "Training strictly on benign traffic forces the model to construct an empirical structural profile of normality. The anomaly decision function "
        "yields a continuous score s(x), where lower values represent greater anomaly depth."
    )

    add_h2("11.3 Leakage-Free Threshold Calibration")
    p = doc.add_paragraph()
    p.add_run(
        "Rather than utilizing scikit-learn's default zero-threshold or tuning against the test set, the anomaly threshold was calibrated via a systematic "
        "grid search across percentiles 1% to 20% on the independent validation split. The threshold maximizing validation F1-score was established at:\n"
        "Threshold t = 0.061102 (Validation F1 = 0.5744, Precision = 0.5621, Recall = 0.5872)."
    )

    add_h2("11.4 Hybrid Decision & Severity Triage Logic")
    p = doc.add_paragraph()
    p.add_run(
        "The hybrid detector executes a deterministic, multi-tiered arbitration policy:\n"
        "1. Priority 1 (Known Attack): If Random Forest predicts an attack category (RF != BENIGN), the system preserves the specific attack label and assigns HIGH severity.\n"
        "2. Priority 2 (Novel Anomaly): If Random Forest predicts BENIGN, but the Isolation Forest decision score falls below threshold (s(x) < 0.061102), "
        "the flow is flagged as 'Anomaly (Unclassified)' and assigned MEDIUM severity.\n"
        "3. Priority 3 (Confirmed Normal): If Random Forest predicts BENIGN and Isolation Forest score exceeds threshold, the flow is designated BENIGN with INFO severity."
    )

    # ---------------------------------------------------------
    # 12. EXPLAINABILITY & ALERT GROUPING
    # ---------------------------------------------------------
    add_h1("12. Explainability & Alert Grouping")

    add_h2("12.1 Local Explainability via SHAP TreeExplainer")
    p = doc.add_paragraph()
    p.add_run(
        "To provide auditable justification for classifier alerts, the system integrates SHAP TreeExplainer. When a flow triggers a HIGH-severity alert, "
        "TreeExplainer extracts the exact Shapley values for the predicted attack class, highlighting the top 20 features driving the classification. "
        "For instance, DoS Hulk alerts are predominantly explained by extreme Bwd Packet Length Max and Flow Duration, while PortScan alerts are driven "
        "by Destination Port diversity and null backward packet counts."
    )

    add_h2("12.2 Alert Grouping & Fatigue Mitigation")
    p = doc.add_paragraph()
    p.add_run(
        "In enterprise SOC environments, high-throughput network attacks generate massive streams of repetitive, flow-level alerts. The AlertGrouper engine "
        "implements a sliding-window aggregation algorithm (default window: 60 seconds; min_alerts threshold: 5 flows). Individual flows sharing the same "
        "final_label and severity within the temporal or sequential window are aggregated into consolidated AlertGroup units containing flow count, "
        "average classifier confidence, average anomaly score, and temporal boundaries."
    )

    # ---------------------------------------------------------
    # 13. SOFTWARE IMPLEMENTATION & DASHBOARD MODULES
    # ---------------------------------------------------------
    add_h1("13. Software Implementation & Dashboard Modules")

    p = doc.add_paragraph()
    p.add_run("The software architecture is implemented across modular, decoupled Python components:")
    src_items = [
        ("src/audit_dataset.py", "Performs initial chunked file audit, checking dimensions, missing cells, infinities, and labels."),
        ("src/preprocess.py", "Executes column filtering, infinite/NaN imputation, deduplication, withheld splitting, and parquet generation."),
        ("src/train_rf.py", "Fits the 200-tree balanced Random Forest and exports model, scaler, and validation metrics."),
        ("src/train_iforest.py", "Fits the benign Isolation Forest and optimizes the decision threshold on validation data."),
        ("src/hybrid.py", "Encapsulates HybridDetector class, coordinating dual-engine inference and severity triage."),
        ("src/evaluate_hybrid.py", "Executes full comparative benchmarking across test and withheld splits, exporting reports/eval_results.json."),
        ("src/alert_grouper.py", "Implements sliding-window AlertGrouper and conversion to analytical dataframes."),
        ("dashboard/app.py", "Interactive 5-page Streamlit security application.")
    ]
    for f, d in src_items:
        p_s = doc.add_paragraph()
        r_f = p_s.add_run(f"• {f}: ")
        r_f.bold = True
        p_s.add_run(d)

    add_h2("13.1 Dashboard Architecture")
    p = doc.add_paragraph()
    p.add_run(
        "The Streamlit dashboard (dashboard/app.py) features a dark-themed SOC interface structured into five operational views:\n"
        "1. Overview: High-level system KPIs, model macro-F1, FPR, withheld experiment detection summaries, and raw dataset catalog.\n"
        "2. Live Prediction: Allows operators to sample the test split or upload arbitrary CSV flows, running real-time hybrid inference.\n"
        "3. Alert Triage: Displays aggregated alert groups with severity filtering (HIGH, MEDIUM, INFO) to manage investigation queues.\n"
        "4. Explainability: Generates interactive SHAP horizontal bar plots and waterfall visualizations for selected alert rows.\n"
        "5. Anomaly Analysis: Visualizes Isolation Forest score distributions across traffic classes and compares withheld detection rates."
    )

    # ---------------------------------------------------------
    # 14. EXPERIMENTAL DESIGN & EVALUATION METRICS
    # ---------------------------------------------------------
    add_h1("14. Experimental Design & Evaluation Metrics")

    p = doc.add_paragraph()
    p.add_run(
        "Evaluation was executed strictly on unseen partitions: the 504,037-row known-category test split and the 2,179-row withheld dataset. "
        "Standard statistical metrics were computed using scikit-learn:\n"
        "• Precision = TP / (TP + FP)\n"
        "• Recall = TP / (TP + FN)\n"
        "• F1-Score = 2 * (Precision * Recall) / (Precision + Recall)\n"
        "• False Positive Rate (FPR) = FP / (FP + TN)\n"
        "• False Negative Rate (FNR) = FN / (FN + TP)\n"
        "• Macro-Averaged F1: Unweighted arithmetic mean of per-class F1-scores, ensuring minority attacks are evaluated equally with majority classes."
    )

    # ---------------------------------------------------------
    # 15. RESULTS, TABLES, CHARTS & DETAILED INTERPRETATION
    # ---------------------------------------------------------
    add_h1("15. Results, Tables, Charts & Detailed Interpretation")

    add_h2("15.1 Baseline Random Forest Multiclass Performance")
    p = doc.add_paragraph()
    p.add_run(
        "Table 3 presents the complete, verified multiclass classification report for the supervised Random Forest on the 504,037 test split flows."
    )

    tbl_rf = doc.add_table(rows=14, cols=5)
    tbl_rf.alignment = WD_TABLE_ALIGNMENT.CENTER
    rf_head = ["Traffic Class", "Precision", "Recall", "F1-Score", "Test Support"]
    w_rf = [Inches(2.2), Inches(1.1), Inches(1.1), Inches(1.1), Inches(1.2)]
    for i, title in enumerate(rf_head):
        tbl_rf.rows[0].cells[i].paragraphs[0].text = title
    style_table_header(tbl_rf.rows[0], w_rf)

    rf_results = [
        ("BENIGN", "0.9999", "0.9974", "0.9987", "419,297"),
        ("Bot", "0.3525", "0.9744", "0.5177", "391"),
        ("DDoS", "0.9995", "0.9997", "0.9996", "25,603"),
        ("DoS GoldenEye", "0.9898", "0.9951", "0.9925", "2,057"),
        ("DoS Hulk", "0.9952", "0.9992", "0.9972", "34,570"),
        ("DoS Slowhttptest", "0.9858", "0.9943", "0.9900", "1,046"),
        ("DoS slowloris", "0.9944", "0.9935", "0.9940", "1,077"),
        ("FTP-Patator", "0.9983", "0.9992", "0.9987", "1,186"),
        ("Heartbleed", "0.6667", "1.0000", "0.8000", "2"),
        ("PortScan", "0.9900", "0.9992", "0.9945", "18,164"),
        ("SSH-Patator", "1.0000", "0.9938", "0.9969", "644"),
        ("Macro Average", "0.9065", "0.9951", "0.9345", "504,037"),
        ("Weighted Average", "0.9986", "0.9977", "0.9980", "504,037")
    ]
    for r_idx, r_data in enumerate(rf_results):
        row = tbl_rf.rows[r_idx + 1]
        for c_idx, val in enumerate(r_data):
            row.cells[c_idx].paragraphs[0].text = val
        bg = "EDF2F7" if "Average" in r_data[0] else ("F7FAFC" if r_idx % 2 == 1 else "FFFFFF")
        style_table_row(row, w_rf, bg, [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.RIGHT])

    p_cap3 = doc.add_paragraph()
    p_cap3.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_cap3 = p_cap3.add_run("Table 3: Multiclass classification metrics for Random Forest on the held-out test split.")
    r_cap3.font.size = Pt(8.5)
    r_cap3.font.italic = True

    add_callout(
        doc,
        "Investigation of Bot Class Precision (0.3525): The Bot class exhibits a precision of only 35.25%, despite an exceptional recall of 97.44%. "
        "Out of 1,081 flows predicted as Bot by the Random Forest, only 381 were true Bot records, while 700 benign flows were misclassified as Bot. "
        "In CIC-IDS2017, the Bot attack comprises Ares botnet traffic communicating via HTTP/IRC. Ares background traffic exhibits packet size distributions "
        "and window parameters that overlap heavily with standard workstation web browsing, producing high false positive sensitivity.",
        "Crucial Empirical Finding"
    )

    add_h2("15.2 Comparative Evaluation: Random Forest vs. Hybrid System")
    p = doc.add_paragraph()
    p.add_run(
        "Table 4 compares the binary performance of the Random Forest baseline against the Hybrid System on the 504,037 test flows."
    )

    tbl_hyb = doc.add_table(rows=8, cols=4)
    tbl_hyb.alignment = WD_TABLE_ALIGNMENT.CENTER
    hyb_head = ["Evaluation Metric", "RF-Only Baseline", "Hybrid Detector", "Operational Impact"]
    w_hyb = [Inches(2.0), Inches(1.3), Inches(1.3), Inches(2.1)]
    for i, title in enumerate(hyb_head):
        tbl_hyb.rows[0].cells[i].paragraphs[0].text = title
    style_table_header(tbl_hyb.rows[0], w_hyb)

    hyb_results = [
        ("Binary Precision", "98.75% (0.9875)", "68.21% (0.6821)", "-30.54% (Diluted by Anomaly FPs)"),
        ("Binary Recall", "99.94% (0.9994)", "99.95% (0.9995)", "+0.01% (+5 Attack Flows Caught)"),
        ("Binary F1-Score", "99.34% (0.9934)", "81.08% (0.8108)", "-18.26% (Harmonic Penalty)"),
        ("False Positive Rate (FPR)", "0.26% (0.0026)", "9.42% (0.0942)", "36.2x Increase in False Alarms"),
        ("False Alarm Count (FP)", "1,072 flows", "39,477 flows", "+38,405 Spurious Alert Rows"),
        ("True Negative Count (TN)", "418,225 flows", "379,820 flows", "38,405 Benign Flows Flagged"),
        ("Total Alerts Generated", "85,762 alerts", "124,172 alerts", "+44.8% Increase in Triage Volume")
    ]
    for r_idx, r_data in enumerate(hyb_results):
        row = tbl_hyb.rows[r_idx + 1]
        for c_idx, val in enumerate(r_data):
            row.cells[c_idx].paragraphs[0].text = val
        bg = "F7FAFC" if r_idx % 2 == 1 else "FFFFFF"
        style_table_row(row, w_hyb, bg, [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.LEFT])

    p_cap4 = doc.add_paragraph()
    p_cap4.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_cap4 = p_cap4.add_run("Table 4: Comparative binary detection metrics on known attacks test split (N=504,037).")
    r_cap4.font.size = Pt(8.5)
    r_cap4.font.italic = True

    # Insert Fig 4
    if Path("reports/figures/fig4_rf_vs_hybrid_metrics.png").exists():
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_picture("reports/figures/fig4_rf_vs_hybrid_metrics.png", width=Inches(5.6))
        p_f4 = doc.add_paragraph()
        p_f4.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f4 = p_f4.add_run("Figure 4: Performance comparison between RF-Only and Hybrid models on the test split.")
        r_f4.font.size = Pt(8.5)
        r_f4.font.italic = True

    add_h2("15.3 Withheld-Category Experiment Results")
    p = doc.add_paragraph()
    p.add_run(
        "Table 5 details the core scientific experiment of this project: evaluating detection effectiveness on the 2,179 attack flows completely "
        "withheld from supervised training."
    )

    tbl_with = doc.add_table(rows=6, cols=6)
    tbl_with.alignment = WD_TABLE_ALIGNMENT.CENTER
    with_head = ["Withheld Attack Category", "Total Flows", "RF Detected", "IF Detected", "Hybrid Detected", "Primary Failure / Success Mechanism"]
    w_wth = [Inches(2.0), Inches(0.8), Inches(0.9), Inches(0.9), Inches(0.9), Inches(1.8)]
    for i, title in enumerate(with_head):
        tbl_with.rows[0].cells[i].paragraphs[0].text = title
    style_table_header(tbl_with.rows[0], w_wth)

    with_results = [
        ("Infiltration", "36", "0 (0.0%)", "31 (86.11%)", "31 (86.11%)", "IF caught anomalous payload transfer; RF 100% blind (BENIGN)."),
        ("Web Attack – Brute Force", "1,470", "69 (4.69%)", "74 (5.03%)", "143 (9.73%)", "Flow statistics mimic normal HTTP; RF assigned slowloris/Hulk."),
        ("Web Attack – XSS", "652", "21 (3.22%)", "18 (2.76%)", "39 (5.98%)", "HTTP payload invisible at transport flow layer."),
        ("Web Attack – Sql Injection", "21", "4 (19.05%)", "0 (0.00%)", "4 (19.05%)", "Zero structural anomaly; RF misclassified 4 as GoldenEye/Hulk."),
        ("Total / Aggregate", "2,179", "94 (4.31%)", "123 (5.64%)", "217 (9.96%)", "Hybrid achieves 2.3x higher novel detection than RF alone.")
    ]
    for r_idx, r_data in enumerate(with_results):
        row = tbl_with.rows[r_idx + 1]
        for c_idx, val in enumerate(r_data):
            row.cells[c_idx].paragraphs[0].text = val
        bg = "EDF2F7" if "Total" in r_data[0] else ("F7FAFC" if r_idx % 2 == 1 else "FFFFFF")
        style_table_row(row, w_wth, bg, [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.RIGHT, WD_ALIGN_PARAGRAPH.LEFT])

    p_cap5 = doc.add_paragraph()
    p_cap5.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_cap5 = p_cap5.add_run("Table 5: Detection rates on withheld attack categories never shown during supervised training.")
    r_cap5.font.size = Pt(8.5)
    r_cap5.font.italic = True

    # Insert Fig 5
    if Path("reports/figures/fig5_withheld_detection.png").exists():
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_picture("reports/figures/fig5_withheld_detection.png", width=Inches(5.8))
        p_f5 = doc.add_paragraph()
        p_f5.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f5 = p_f5.add_run("Figure 5: Detection rate comparison across withheld attack categories.")
        r_f5.font.size = Pt(8.5)
        r_f5.font.italic = True

    add_callout(
        doc,
        "Critical Evaluation of the 86.11% Infiltration Detection: While the Isolation Forest successfully detected 31 of 36 Infiltration flows, "
        "the small sample size (N = 36) introduces substantial statistical uncertainty. The 95% Wilson score confidence interval spans [71.3%, 93.9%]. "
        "Furthermore, an anomaly detector flagging a flow as anomalous does not constitute semantic attack identification: the system alerts that traffic "
        "deviates from normality, requiring human investigation to verify whether the deviation represents malicious exploitation or benign network drift.",
        "Statistical Rigor & Sample Size Caution"
    )

    # Insert Fig 6
    if Path("reports/figures/fig6_anomaly_distribution.png").exists():
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_picture("reports/figures/fig6_anomaly_distribution.png", width=Inches(5.8))
        p_f6 = doc.add_paragraph()
        p_f6.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f6 = p_f6.add_run("Figure 6: Density distribution of Isolation Forest anomaly scores across benign, attack, and unclassified anomaly traffic.")
        r_f6.font.size = Pt(8.5)
        r_f6.font.italic = True

    add_h2("15.4 Feature Importance Analysis")
    p = doc.add_paragraph()
    p.add_run(
        "Analysis of Gini feature importances within the trained Random Forest reveals the primary flow characteristics governing decisions. "
        "As depicted in Figure 7, Destination Port represents the single most informative feature (Gini = 0.0596), followed by backward header lengths, "
        "maximum backward packet lengths, and TCP initial window advertisement sizes (Init_Win_bytes_backward and Init_Win_bytes_forward)."
    )

    # Insert Fig 7
    if Path("reports/figures/fig7_top_features.png").exists():
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_picture("reports/figures/fig7_top_features.png", width=Inches(5.8))
        p_f7 = doc.add_paragraph()
        p_f7.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f7 = p_f7.add_run("Figure 7: Top 15 most informative features ranked by Gini importance in the Random Forest model.")
        r_f7.font.size = Pt(8.5)
        r_f7.font.italic = True

    add_h2("15.5 Latency & Alert Triage Benchmarking")
    p = doc.add_paragraph()
    p.add_run(
        "To satisfy the operational performance requirements outlined in the project proposal, inference latency and alert grouping efficiency "
        "were benchmarked on an empirical test batch of 10,000 flows:\n"
        "• Feature Scaling Latency: 0.57 microseconds per flow (5.74 ms total batch time).\n"
        "• Random Forest Classifier Latency: 5.59 microseconds per flow (~178,950 flows/second throughput).\n"
        "• Isolation Forest Anomaly Scoring Latency: 5.73 microseconds per flow (~174,450 flows/second throughput).\n"
        "• Complete End-to-End Hybrid Pipeline Latency: 15.79 microseconds per flow (~63,330 flows/second throughput).\n"
        "• Alert Grouping Compression: Across 10,000 sample flows, 2,483 individual flow alerts (HIGH + MEDIUM) were generated. The AlertGrouper "
        "compressed these into 11 consolidated AlertGroup incidents, achieving a 99.56% reduction in triage events."
    )

    # Insert Fig 8
    if Path("reports/figures/fig8_alert_compression.png").exists():
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_picture("reports/figures/fig8_alert_compression.png", width=Inches(4.8))
        p_f8 = doc.add_paragraph()
        p_f8.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f8 = p_f8.add_run("Figure 8: Alert triage compression demonstrating mitigation of analyst alert fatigue.")
        r_f8.font.size = Pt(8.5)
        r_f8.font.italic = True

    # ---------------------------------------------------------
    # 16. DISCUSSION & RESEARCH QUESTION ANSWERS
    # ---------------------------------------------------------
    add_h1("16. Discussion & Synthesis of Research Questions")

    p = doc.add_paragraph()
    p.add_run("Synthesizing the verified empirical evidence provides conclusive answers to the four foundational research questions:")

    rq_answers = [
        ("RQ1: Supervised Classifier Fidelity",
         "The Random Forest model demonstrates exceptional fidelity on known attack patterns, achieving a test Macro-F1 of 0.9345, weighted-F1 of 0.9980, "
         "binary recall of 99.94%, and a negligible false positive rate of 0.26%. However, fidelity is not uniform across classes: volumetric attacks "
         "(DDoS, DoS Hulk, PortScan) achieve near-perfect F1 (> 0.99), whereas minority and behaviorally subtle threats exhibit lower precision, most "
         "prominently illustrated by the Bot class (Precision = 0.3525)."),

        ("RQ2: Isolation Forest on Withheld Categories",
         "The unsupervised Isolation Forest successfully detects structural deviations when the attack generates distinct flow dynamics, as proven by "
         "flagging 86.11% of Infiltration flows. However, it fails completely on semantic web-layer attacks (detecting only 5.03% of Brute Force, 2.76% of XSS, "
         "and 0.0% of SQL Injection). This establishes that statistical transport flow features are blind to application-layer malicious payloads."),

        ("RQ3: Hybrid Trade-Off & False Positive Cost",
         "The hybrid system successfully bridges the classifier's total blindness to novel Infiltration attacks (raising detection from 0.0% to 86.11%) and "
         "increases aggregate novel attack detection from 4.31% to 9.96%. However, this gain comes at a severe operational cost: on known traffic, the false "
         "positive rate surges 36.2-fold from 0.26% to 9.42%, generating 38,405 spurious alerts on the test split. Thus, hybrid anomaly detection cannot be "
         "deployed naively without tiered severity filtering."),

        ("RQ4: Utility of Explainability & Alert Triage",
         "SHAP TreeExplainer successfully demystifies Random Forest decisions by attributing high-magnitude weights to defining features (e.g., Destination Port, "
         "Bwd Packet Length Max). Concurrently, the sliding-window Alert Grouper compresses raw flow alerts by 99.56%, transforming an unmanageable barrage of "
         "individual alerts into structured triage incidents.")
    ]

    for title, ans in rq_answers:
        add_h2(title)
        p_a = doc.add_paragraph()
        p_a.add_run(ans)

    # ---------------------------------------------------------
    # 17. LIMITATIONS, THREATS TO VALIDITY & ETHICS
    # ---------------------------------------------------------
    add_h1("17. Limitations, Threats to Validity & Ethical Considerations")

    add_h2("17.1 Infiltration Sample Size & Statistical Power")
    p = doc.add_paragraph()
    p.add_run(
        "A severe threat to statistical validity is the extreme scarcity of Infiltration records in CIC-IDS2017 (only 36 flows post-deduplication). "
        "While catching 31 of 36 flows is promising, a sample of 36 cannot support definitive claims of generalizable zero-day detection."
    )

    add_h2("17.2 Confounding in CIC-IDS2017 Testbed Generation")
    p = doc.add_paragraph()
    p.add_run(
        "As documented by Engelen et al. (2021) and Lanvin et al. (2023), CIC-IDS2017 exhibits experimental confounding. Attack scenarios were executed on "
        "distinct days of the week from specific IP addresses. Furthermore, pandas identified duplicate column names (Fwd Header Length and Fwd Header Length.1) "
        "present in the original raw CSV files. While socket metadata was dropped, temporal and host configuration artifacts may partially persist in flow statistics."
    )

    add_h2("17.3 Ethical & Operational Boundaries")
    p = doc.add_paragraph()
    p.add_run(
        "This project evaluates offline historical dataset records. Deploying machine learning IDS models on live production networks requires authorization, "
        "adherence to privacy regulations (e.g., GDPR when inspecting packet headers), and human-in-the-loop validation to prevent automated denial-of-service "
        "against legitimate users."
    )

    # ---------------------------------------------------------
    # 18. TESTING & SOFTWARE VERIFICATION
    # ---------------------------------------------------------
    add_h1("18. Testing & Software Verification")

    p = doc.add_paragraph()
    p.add_run(
        "To ensure robust software engineering, the codebase incorporates a comprehensive automated test suite (tests/test_hybrid.py) executed via pytest. "
        "Table 6 documents the test verification matrix."
    )

    tbl_test = doc.add_table(rows=11, cols=4)
    tbl_test.alignment = WD_TABLE_ALIGNMENT.CENTER
    test_head = ["Test Function", "Target Module", "Verified Behavior", "Execution Status"]
    w_tst = [Inches(2.4), Inches(1.3), Inches(2.2), Inches(0.8)]
    for i, title in enumerate(test_head):
        tbl_test.rows[0].cells[i].paragraphs[0].text = title
    style_table_header(tbl_test.rows[0], w_tst)

    test_cases = [
        ("test_predict_returns_correct_count", "HybridDetector", "Verifies output record count matches input batch size.", "PASSED"),
        ("test_known_attack_is_high", "HybridDetector", "Ensures RF attack classifications yield HIGH severity.", "PASSED"),
        ("test_benign_rf_anomaly_if_is_medium", "HybridDetector", "Verifies RF Benign + IF anomaly yields MEDIUM severity.", "PASSED"),
        ("test_both_benign_is_info", "HybridDetector", "Ensures RF Benign + IF normal yields INFO severity.", "PASSED"),
        ("test_predict_df_adds_columns", "HybridDetector", "Validates dataframe column enrichment and data types.", "PASSED"),
        ("test_no_group_below_min", "AlertGrouper", "Verifies flow counts below min_alerts do not form groups.", "PASSED"),
        ("test_single_group_above_min", "AlertGrouper", "Validates group formation when count exceeds threshold.", "PASSED"),
        ("test_groups_to_dataframe", "AlertGrouper", "Ensures correct schema in converted alert dataframes.", "PASSED"),
        ("test_multiple_groups", "AlertGrouper", "Verifies separation of distinct label/severity clusters.", "PASSED"),
        ("test_empty_dataframe", "AlertGrouper", "Validates graceful handling of empty input frames.", "PASSED")
    ]
    for r_idx, r_data in enumerate(test_cases):
        row = tbl_test.rows[r_idx + 1]
        for c_idx, val in enumerate(r_data):
            row.cells[c_idx].paragraphs[0].text = val
        bg = "F7FAFC" if r_idx % 2 == 1 else "FFFFFF"
        style_table_row(row, w_tst, bg, [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER])

    p_cap6 = doc.add_paragraph()
    p_cap6.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_cap6 = p_cap6.add_run("Table 6: Automated unit test suite execution matrix (10/10 tests passing).")
    r_cap6.font.size = Pt(8.5)
    r_cap6.font.italic = True

    # ---------------------------------------------------------
    # 19. CONCLUSION & FUTURE WORK
    # ---------------------------------------------------------
    add_h1("19. Conclusion & Future Work")

    p = doc.add_paragraph()
    p.add_run(
        "This project successfully designed, implemented, and empirically evaluated a hybrid machine learning Network Intrusion Detection System. "
        "The supervised Random Forest achieved exceptional fidelity on known attacks (Macro-F1 = 0.9345, Binary Recall = 99.94%), while the Isolation "
        "Forest demonstrated the tangible capability of unsupervised learning to detect withheld Infiltration attacks (86.11% detection rate) where the "
        "supervised model was 100% blind. Concurrently, the study rigorously exposed the critical limitations of hybrid systems: an alarming rise in false "
        "positive rates (0.26% to 9.42%) and complete blindness to web payload attacks that mirror benign transport profiles. By integrating SHAP explainability "
        "and sliding-window alert grouping (99.56% compression), the system provides a realistic, defensible blueprint for next-generation SOC operations."
    )

    add_h2("19.1 Future Research Directions")
    p = doc.add_paragraph()
    p.add_run(
        "Key avenues for future extension include:\n"
        "1. Deep Packet Payload Fusion: Integrating natural language processing (e.g., character-level CNNs or Transformers) on HTTP URIs and headers to detect SQLi and XSS.\n"
        "2. Dynamic Threshold Adaptation: Implementing streaming adaptive thresholds for the Isolation Forest based on time-of-day traffic seasonality.\n"
        "3. Live Snort / Zeek Integration: Deploying the hybrid detector as an asynchronous analysis plugin over live Zeek connection logs."
    )

    # ---------------------------------------------------------
    # 20. REFERENCES
    # ---------------------------------------------------------
    add_h1("20. References")

    refs = [
        "Ahmad, Z., Shahid Khan, A., Che Wai Shiang, C., Abdullah, J., & Ahmad, F. (2021). Network intrusion detection system: A systematic study of machine learning and deep learning approaches. Transactions on Emerging Telecommunications Technologies, 32(1), e4150. https://doi.org/10.1002/ett.4150",
        "Breiman, L. (2001). Random Forests. Machine Learning, 45(1), 5–32. https://doi.org/10.1023/A:1010933404324",
        "Engelen, G., Rimmer, V., & Joosen, W. (2021). Troubleshooting an Incomplete Machine Learning Anomaly Detection Pipeline: A Case Study on CIC-IDS2017. In Proceedings of the 2021 ACM Workshop on Artificial Intelligence and Security (AISEC '21), 25–35. https://doi.org/10.1145/3474369.3486866",
        "Lanvin, N., Sommer, R., & Cavalli, A. (2023). Errors in the CICIDS2017 dataset and their impact on ML-based network intrusion detection. IEEE Transactions on Network and Service Management, 20(3), 2874–2888.",
        "Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. In 2008 Eighth IEEE International Conference on Data Mining (ICDM), 413–422. https://doi.org/10.1109/ICDM.2008.17",
        "Lundberg, S. M., & Lee, S. I. (2017). A Unified Approach to Interpreting Model Predictions. In Advances in Neural Information Processing Systems 30 (NeurIPS 2017), 4765–4774.",
        "Lundberg, S. M., Erion, G., Chen, H., DeGrave, A., Prutkin, J. M., Nair, B., Katz, R., Himmelfarb, J., Bansal, N., & Lee, S. I. (2020). From local explanations to global understanding with explainable AI for trees. Nature Machine Intelligence, 2(1), 56–67. https://doi.org/10.1038/s42256-019-0138-9",
        "Rosay, A., Carlier, F., & Leroux, B. (2022). Improving CIC-IDS-2017 with new missing flows and realistic evaluation. In 2022 IEEE 47th Conference on Local Computer Networks (LCN), 345–352. https://doi.org/10.1109/LCN53696.2022.9843644",
        "Sarhan, M., Layeghy, S., & Portmann, M. (2021). Evaluating machine learning algorithms for network intrusion detection using standard data sets. IEEE Access, 9, 87638–87654. https://doi.org/10.1109/ACCESS.2021.3089456",
        "Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. In Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP 2018), 108–116. https://doi.org/10.5220/0006639801080116"
    ]
    for rf in refs:
        p_r = doc.add_paragraph()
        p_r.paragraph_format.left_indent = Inches(0.4)
        p_r.paragraph_format.first_line_indent = Inches(-0.4)
        p_r.add_run(rf)

    # ---------------------------------------------------------
    # 21. APPENDICES
    # ---------------------------------------------------------
    add_h1("21. Appendices")

    add_h2("Appendix A: Repository Structure & Artifact Layout")
    p = doc.add_paragraph()
    p.add_run(
        "network-ids/\n"
        "├── Makefile                     (Automated build pipeline targets)\n"
        "├── README.md                    (Project documentation & quick-start)\n"
        "├── requirements.txt             (Python dependencies)\n"
        "├── dashboard/\n"
        "│   └── app.py                   (5-page Streamlit SOC dashboard)\n"
        "├── data/\n"
        "│   ├── raw/MachineLearningCVE/  (8 raw CIC-IDS2017 CSV files, ~885 MB)\n"
        "│   └── processed/               (train, val, test, withheld parquets; features & label maps)\n"
        "├── models/\n"
        "│   ├── rf_model.pkl             (Trained 200-tree Random Forest, 82.2 MB)\n"
        "│   ├── rf_scaler.pkl            (StandardScaler fit on train split)\n"
        "│   ├── rf_eval.json             (Validation evaluation metrics)\n"
        "│   ├── iforest_model.pkl        (Trained Isolation Forest, 1.46 MB)\n"
        "│   ├── iforest_threshold.json   (Optimized anomaly threshold: 0.061102)\n"
        "│   └── iforest_eval.json        (Validation evaluation metrics)\n"
        "├── reports/\n"
        "│   ├── dataset_audit.txt        (Raw CSV file audit log)\n"
        "│   ├── eval_results.json        (Test & withheld experiment results)\n"
        "│   └── figures/                 (Publication-grade charts & diagrams)\n"
        "├── src/\n"
        "│   ├── alert_grouper.py         (Sliding-window alert aggregation engine)\n"
        "│   ├── audit_dataset.py         (Data quality auditing script)\n"
        "│   ├── evaluate_hybrid.py       (Full evaluation & withheld experiment script)\n"
        "│   ├── hybrid.py                (HybridDetector class & triage logic)\n"
        "│   ├── preprocess.py            (Cleaning, deduplication & splitting pipeline)\n"
        "│   ├── train_iforest.py         (Isolation Forest training & threshold sweep)\n"
        "│   └── train_rf.py              (Random Forest training & multiclass evaluation)\n"
        "└── tests/\n"
        "    └── test_hybrid.py           (Automated pytest unit tests)\n"
    )
    p.runs[0].font.name = 'Courier New'
    p.runs[0].font.size = Pt(8.5)

    add_h2("Appendix B: Reproducibility & Execution Commands")
    p = doc.add_paragraph()
    p.add_run(
        "To reproduce the complete pipeline from scratch, execute the following commands:\n"
        "1. Install Dependencies: make install\n"
        "2. Audit Raw Dataset: make audit\n"
        "3. Preprocess & Split Data: make preprocess\n"
        "4. Train Random Forest: make train-rf\n"
        "5. Train Isolation Forest: make train-iforest\n"
        "6. Evaluate Hybrid System: make evaluate\n"
        "7. Execute Test Suite: make test\n"
        "8. Launch SOC Dashboard: make dashboard"
    )

    doc.save(filename)
    print(f"Document saved successfully to {filename}")

if __name__ == "__main__":
    build_docx()
