# -*- coding: utf-8 -*-
"""
Gerador de relatórios em múltiplos formatos: JSON, CSV, HTML, XML, Markdown, texto.
Portado do V1 (main.py) para uso modular.
"""
import csv
import html as html_lib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from core.config import Config
from reports.findings import collect_findings, count_by_severity, explain, sort_by_severity

VERSION = '6.0.0-unified'


class ReportGenerator:
    """Gerador de relatórios em múltiplos formatos (JSON, CSV, HTML, XML, Markdown, texto)."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = Path(output_dir) if output_dir else Config.REPORTS_DIR
        self.output_dir.mkdir(exist_ok=True, parents=True)

    def generate(self, data: Any, fmt: str, filename: str = None,
                 title: str = "Relatório Mão de Deus") -> str:
        if not filename:
            filename = f"relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        dispatch = {
            "json": self._json,
            "csv": self._csv,
            "html": self._html,
            "xml": self._xml,
            "markdown": self._markdown,
            "text": self._text,
            "pdf": self._pdf,
        }
        fn = dispatch.get(fmt, self._text)
        return fn(data, filename, title)

    # ---- JSON ----
    def _json(self, data, filename, title):
        p = self.output_dir / f"{filename}.json"
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return str(p)

    # ---- CSV ----
    def _csv(self, data, filename, title):
        p = self.output_dir / f"{filename}.csv"
        rows = data if isinstance(data, list) else [data]
        if rows and isinstance(rows[0], dict):
            fields = list(rows[0].keys())
            with open(p, 'w', newline='', encoding='utf-8') as f:
                w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
                w.writeheader()
                for row in rows:
                    flat = {k: (json.dumps(v, default=str, ensure_ascii=False)
                                if isinstance(v, (dict, list)) else v)
                            for k, v in row.items()}
                    w.writerow(flat)
        return str(p)

    # ---- HTML ----
    def _html(self, data, filename, title):
        p = self.output_dir / f"{filename}.html"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def _to_html(obj):
            if isinstance(obj, dict):
                rows = ""
                for k, v in obj.items():
                    if str(k).startswith('_'):
                        continue
                    rows += f"<tr><td class='key'><b>{html_lib.escape(str(k))}</b></td><td>{_to_html(v)}</td></tr>"
                return f"<table class='inner'>{rows}</table>"
            if isinstance(obj, list):
                if not obj:
                    return "<em>vazio</em>"
                items = "".join(f"<li>{_to_html(i)}</li>" for i in obj)
                return f"<ul>{items}</ul>"
            if obj is None:
                return "<span class='na'>N/A</span>"
            if isinstance(obj, bool):
                cls = 'ok' if obj else 'bad'
                return f"<span class='badge {cls}'>{'Sim' if obj else 'Não'}</span>"
            s = str(obj)
            if s.startswith(('http://', 'https://')):
                return f"<a href='{s}' target='_blank'>{html_lib.escape(s)}</a>"
            return html_lib.escape(s)

        body = _to_html(data)
        content = f"""<!DOCTYPE html><html lang='pt-BR'><head><meta charset='UTF-8'>
<title>{html_lib.escape(title)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
  .wrap{{max-width:1400px;margin:0 auto}}
  header{{background:linear-gradient(135deg,#1a2a6c,#b21f1f,#fdbb2d);padding:30px;border-radius:12px;margin-bottom:24px}}
  header h1{{font-size:2em;color:#fff;text-shadow:0 2px 8px #0008}}
  header small{{color:#eee;font-size:.85em}}
  table.inner{{border-collapse:collapse;width:100%;margin:4px 0}}
  table.inner td{{border:1px solid #30363d;padding:6px 10px;vertical-align:top;font-size:.88em}}
  td.key{{background:#161b22;min-width:160px;color:#79c0ff}}
  ul{{margin-left:20px;padding:4px 0}}
  li{{margin:3px 0;font-size:.88em}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.8em;font-weight:600}}
  .ok{{background:#238636;color:#fff}}.bad{{background:#da3633;color:#fff}}
  .na{{color:#6e7681;font-style:italic}}
  a{{color:#58a6ff;text-decoration:none}}a:hover{{text-decoration:underline}}
  .ts{{float:right;color:#8b949e;font-size:.8em}}
  footer{{text-align:center;margin-top:30px;color:#6e7681;font-size:.8em}}
</style></head><body><div class='wrap'>
<header><h1>Mão de Deus — {html_lib.escape(title)}</h1>
<small class='ts'>Gerado: {ts} | v{VERSION}</small></header>
{body}
<footer>Mão de Deus UNIFIED v{VERSION} &mdash; {ts}</footer>
</div></body></html>"""
        with open(p, 'w', encoding='utf-8') as f:
            f.write(content)
        return str(p)

    # ---- XML ----
    def _xml(self, data, filename, title):
        p = self.output_dir / f"{filename}.xml"

        def _to_xml(obj, tag="item", level=1):
            indent = "  " * level
            tag = re.sub(r'[^a-zA-Z0-9_\-]', '_', str(tag)) or 'item'
            if isinstance(obj, dict):
                inner = "".join(_to_xml(v, k, level + 1) for k, v in obj.items())
                return f"{indent}<{tag}>\n{inner}{indent}</{tag}>\n"
            if isinstance(obj, list):
                inner = "".join(_to_xml(i, "item", level + 1) for i in obj)
                return f"{indent}<{tag}>\n{inner}{indent}</{tag}>\n"
            v = html_lib.escape(str(obj)) if obj is not None else ""
            return f"{indent}<{tag}>{v}</{tag}>\n"

        content = (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                   f'<relatorio titulo="{html_lib.escape(title)}" '
                   f'data="{datetime.now().isoformat()}" versao="{VERSION}">\n'
                   + _to_xml(data, "dados", 1)
                   + '</relatorio>')
        with open(p, 'w', encoding='utf-8') as f:
            f.write(content)
        return str(p)

    # ---- Markdown ----
    def _markdown(self, data, filename, title):
        p = self.output_dir / f"{filename}.md"

        def _to_md(obj, level=2):
            if isinstance(obj, dict):
                lines = []
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        lines.append(f"{'#' * level} {k}\n")
                        lines.append(_to_md(v, level + 1))
                    else:
                        lines.append(f"**{k}:** {v}\n\n")
                return "".join(lines)
            if isinstance(obj, list):
                return "".join(f"- {_to_md(i, level) if isinstance(i, (dict, list)) else i}\n"
                               for i in obj) + "\n"
            return str(obj)

        findings = sort_by_severity(collect_findings(data))
        counts = count_by_severity(findings)

        with open(p, 'w', encoding='utf-8') as f:
            f.write(f"# {title}\n\n")
            f.write(f"> Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | v{VERSION}\n\n---\n\n")

            f.write("## Resumo Executivo\n\n")
            f.write("| Severidade | Total |\n|---|---|\n")
            for sev, n in counts.items():
                if n:
                    f.write(f"| {sev} | {n} |\n")
            if not findings:
                f.write("\nNenhuma vulnerabilidade reportada pelos scanners executados.\n")
            f.write("\n---\n\n")

            f.write("## Vulnerabilidades Encontradas\n\n")
            for finding in findings:
                sev = finding.get('severity', 'INFO')
                f.write(f"### [{sev}] {finding.get('title', finding.get('type', 'Finding'))}\n\n")
                if finding.get('description'):
                    f.write(f"**Descrição:** {finding['description']}\n\n")
                if finding.get('affected_url'):
                    f.write(f"**URL afetada:** {finding['affected_url']}\n\n")
                evidence = finding.get('evidence')
                if evidence:
                    ev_str = ', '.join(evidence) if isinstance(evidence, list) else str(evidence)
                    f.write(f"**Evidência:** {ev_str}\n\n")
                if finding.get('remediation'):
                    f.write(f"**Recomendação:** {finding['remediation']}\n\n")
                f.write(f"**O que isto significa:** {explain(finding.get('type', ''))}\n\n")
            f.write("---\n\n")

            f.write(
                "> **Nota:** findings de severidade HIGH baseados em heurísticas simples "
                "(diferença de resposta, palavra-chave presente) podem incluir falsos "
                "positivos e devem ser confirmados manualmente.\n\n"
            )

            f.write("## Dados Completos\n\n")
            f.write(_to_md(data))
        return str(p)

    # ---- PDF ----
    def _pdf(self, data, filename, title):
        from reports.pdf import generate_pdf
        p = self.output_dir / f"{filename}.pdf"
        return generate_pdf(data, p, title)

    # ---- Texto ----
    def _text(self, data, filename, title):
        p = self.output_dir / f"{filename}.txt"
        with open(p, 'w', encoding='utf-8') as f:
            f.write(f"{'=' * 60}\n{title}\n{'=' * 60}\n")
            f.write(f"Data: {datetime.now()}\n\n")
            f.write(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        return str(p)
