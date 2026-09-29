# -*- coding: utf-8 -*-
"""Gerador de relatório PDF (resumo executivo + findings + recomendações)."""

from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from reports.findings import (
    SEVERITY_ORDER, collect_findings, count_by_severity, explain, sort_by_severity,
)

SEVERITY_COLOR = {
    'CRITICAL': colors.HexColor('#8b0000'),
    'HIGH': colors.HexColor('#da3633'),
    'MEDIUM': colors.HexColor('#d29922'),
    'LOW': colors.HexColor('#388bfd'),
    'INFO': colors.HexColor('#6e7681'),
}


def generate_pdf(data: Any, path: Path, title: str = "Relatório Mão de Deus") -> str:
    findings = sort_by_severity(collect_findings(data))
    counts = count_by_severity(findings)

    target = data.get('target') if isinstance(data, dict) else None
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle('h1', parent=styles['Heading1'], textColor=colors.HexColor('#1a2a6c'))
    h2 = ParagraphStyle('h2', parent=styles['Heading2'], spaceBefore=14)
    body = styles['BodyText']
    small = ParagraphStyle('small', parent=styles['BodyText'], fontSize=8, textColor=colors.HexColor('#555'))

    doc = SimpleDocTemplate(str(path), pagesize=A4,
                             topMargin=2 * cm, bottomMargin=2 * cm,
                             leftMargin=2 * cm, rightMargin=2 * cm)
    story = []

    story.append(Paragraph("Mão de Deus — Relatório de Pentest", h1))
    story.append(Paragraph(title, styles['Heading3']))
    meta = f"Alvo: {target or 'N/A'} &nbsp;|&nbsp; Gerado em: {ts}"
    story.append(Paragraph(meta, small))
    story.append(Spacer(1, 0.6 * cm))

    # Resumo executivo
    story.append(Paragraph("Resumo Executivo", h2))
    summary_rows = [["Severidade", "Total"]] + [[s, str(counts[s])] for s in SEVERITY_ORDER if counts[s]]
    if len(summary_rows) == 1:
        summary_rows.append(["Nenhum finding detectado", ""])
    t = Table(summary_rows, colWidths=[8 * cm, 3 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161b22')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.6 * cm))

    # Findings detalhados
    story.append(Paragraph("Vulnerabilidades Encontradas", h2))
    if not findings:
        story.append(Paragraph("Nenhuma vulnerabilidade reportada pelos scanners executados.", body))
    for f in findings:
        sev = f.get('severity', 'INFO')
        color = SEVERITY_COLOR.get(sev, colors.grey)
        title_style = ParagraphStyle('finding_title', parent=styles['Heading4'], textColor=color)
        story.append(Paragraph(f"[{sev}] {f.get('title', f.get('type', 'Finding'))}", title_style))
        if f.get('description'):
            story.append(Paragraph(f"<b>Descrição:</b> {f['description']}", body))
        if f.get('affected_url'):
            story.append(Paragraph(f"<b>URL afetada:</b> {f['affected_url']}", body))
        if f.get('evidence'):
            ev = f['evidence']
            ev_str = ', '.join(ev) if isinstance(ev, list) else str(ev)
            story.append(Paragraph(f"<b>Evidência:</b> {ev_str}", body))
        if f.get('remediation'):
            story.append(Paragraph(f"<b>Recomendação:</b> {f['remediation']}", body))
        story.append(Paragraph(f"<b>O que isto significa:</b> {explain(f.get('type', ''))}", small))
        story.append(Spacer(1, 0.3 * cm))

    # Notas gerais
    story.append(PageBreak())
    story.append(Paragraph("Notas", h2))
    story.append(Paragraph(
        "Este relatório é gerado automaticamente pelos scanners do Mão de Deus. "
        "Findings de severidade HIGH baseados em heurísticas simples (ex: diferença de "
        "tamanho de resposta, presença de palavras-chave) podem incluir falsos positivos "
        "e devem ser confirmados manualmente antes de qualquer ação corretiva.",
        body))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "Use apenas contra alvos para os quais tem autorização explícita de teste.",
        body))

    doc.build(story)
    return str(path)
