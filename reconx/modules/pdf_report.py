from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Circle, String
from reportlab.graphics import renderPDF
from datetime import datetime

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#ea580c"),
    "medium":   colors.HexColor("#d97706"),
    "low":      colors.HexColor("#65a30d"),
    "info":     colors.HexColor("#6b7280"),
}

GRADE_COLORS = {
    "A": colors.HexColor("#16a34a"),
    "B": colors.HexColor("#65a30d"),
    "C": colors.HexColor("#d97706"),
    "D": colors.HexColor("#ea580c"),
    "F": colors.HexColor("#dc2626"),
}

DARK = colors.HexColor("#0f172a")
MID  = colors.HexColor("#1e293b")
LIGHT = colors.HexColor("#f8fafc")


def generate(target: str, findings: list[dict], score: int, grade: str, label: str, output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    normal.fontName = "Helvetica"
    normal.fontSize = 9

    story = []

    # ── Cover ──────────────────────────────────────────────────────────────
    title_style = ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=28,
                                 textColor=DARK, spaceAfter=6)
    sub_style   = ParagraphStyle("sub",   fontName="Helvetica",      fontSize=12,
                                 textColor=colors.HexColor("#64748b"), spaceAfter=4)

    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("Security Reconnaissance Report", title_style))
    story.append(Paragraph(f"Target: <b>{target}</b>", sub_style))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", sub_style))
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=DARK))
    story.append(Spacer(1, 0.5*cm))

    # Risk score gauge
    gauge = _make_gauge(score, grade, label)
    story.append(gauge)
    story.append(Spacer(1, 0.8*cm))

    # ── Summary counts ────────────────────────────────────────────────────
    from collections import Counter
    sev_counts = Counter(f["severity"] for f in findings)
    total_issues = sum(v for k, v in sev_counts.items() if k != "info")

    summary_data = [
        ["Total Findings", "Critical", "High", "Medium", "Low", "Info"],
        [
            str(len(findings)),
            str(sev_counts.get("critical", 0)),
            str(sev_counts.get("high", 0)),
            str(sev_counts.get("medium", 0)),
            str(sev_counts.get("low", 0)),
            str(sev_counts.get("info", 0)),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[3*cm]*6)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), DARK),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 10),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("ROWHEIGHT",  (0,0), (-1,-1), 22),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0,1), (-1,1), LIGHT),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.8*cm))

    # ── Findings by category ──────────────────────────────────────────────
    from itertools import groupby
    sorted_findings = sorted(findings, key=lambda x: (
        ["critical","high","medium","low","info"].index(x["severity"])
    ))

    section_style = ParagraphStyle("section", fontName="Helvetica-Bold", fontSize=13,
                                   textColor=DARK, spaceBefore=14, spaceAfter=4)
    detail_style  = ParagraphStyle("detail",  fontName="Helvetica",      fontSize=8,
                                   textColor=colors.HexColor("#475569"), spaceAfter=2)
    remed_style   = ParagraphStyle("remed",   fontName="Helvetica-Oblique", fontSize=8,
                                   textColor=colors.HexColor("#1d4ed8"))

    story.append(Paragraph("Findings", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 0.3*cm))

    for finding in sorted_findings:
        sev = finding["severity"]
        sev_color = SEVERITY_COLORS.get(sev, colors.gray)
        sev_badge = _badge(sev.upper(), sev_color)

        title_para = Paragraph(f"<b>{finding['title']}</b>", styles["Normal"])
        detail_para = Paragraph(finding["detail"].replace("\n", "<br/>"), detail_style)

        items = [sev_badge, title_para, Spacer(1, 2), detail_para]
        if finding.get("remediation"):
            items.append(Paragraph(f"⚑ {finding['remediation']}", remed_style))

        row = Table([[items]], colWidths=[16.5*cm])
        row.setStyle(TableStyle([
            ("BOX",        (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0,0), (-1,-1), LIGHT),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("RIGHTPADDING",(0,0), (-1,-1), 8),
            ("TOPPADDING",  (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ]))
        story.append(KeepTogether([row, Spacer(1, 4)]))

    # ── Footer note ───────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    footer_style = ParagraphStyle("footer", fontName="Helvetica", fontSize=7,
                                  textColor=colors.HexColor("#94a3b8"))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Generated by Recon-CLI | This report is for authorized use only. "
        "Always obtain written permission before scanning targets you do not own.",
        footer_style
    ))

    doc.build(story)


def _make_gauge(score: int, grade: str, label: str) -> Drawing:
    d = Drawing(500, 110)
    cx, cy, r = 70, 55, 48
    gc = GRADE_COLORS.get(grade, colors.gray)

    # Outer ring
    d.add(Circle(cx, cy, r, fillColor=gc, strokeColor=None))
    d.add(Circle(cx, cy, r-10, fillColor=colors.white, strokeColor=None))

    # Grade letter
    d.add(String(cx, cy+6,  grade, fontName="Helvetica-Bold", fontSize=32,
                 fillColor=gc, textAnchor="middle"))
    d.add(String(cx, cy-18, str(score), fontName="Helvetica", fontSize=11,
                 fillColor=colors.HexColor("#475569"), textAnchor="middle"))

    # Label text
    d.add(String(140, 75, label,  fontName="Helvetica-Bold", fontSize=22, fillColor=gc))
    d.add(String(140, 50, f"Risk Score: {score}/100", fontName="Helvetica", fontSize=12,
                 fillColor=colors.HexColor("#475569")))

    return d


def _badge(text: str, bg_color) -> Paragraph:
    hex_color = bg_color.hexval() if hasattr(bg_color, "hexval") else "#6b7280"
    style = ParagraphStyle(
        "badge",
        fontName="Helvetica-Bold",
        fontSize=7,
        textColor=colors.white,
        backColor=bg_color,
        borderPadding=(2, 4, 2, 4),
        spaceAfter=3,
    )
    return Paragraph(text, style)
