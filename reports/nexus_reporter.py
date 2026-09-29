# -*- coding: utf-8 -*-
"""
Dashboard HTML interativo para resultados do NEXUS Engine (Task 10),
com grafo de força D3.js navegável (zoom, drag, busca).
"""

import html as html_lib
import json
from pathlib import Path
from typing import Any, Dict

from core.config import Config
from modules.intelligence.intel_graph import IntelGraph

VERSION = '6.0.0-unified'

RISK_COLOR = {
    'CRÍTICO': '#F44336',
    'ALTO': '#FF5722',
    'MÉDIO': '#FF9800',
    'BAIXO': '#4CAF50',
}


class NexusReporter:
    """Gera o dashboard HTML (grafo D3.js + achados) de um resultado NEXUS."""

    def generate_dashboard(self, result: Dict[str, Any], graph: IntelGraph,
                            output_path: str = None) -> str:
        if output_path is None:
            safe_target = "".join(c if c.isalnum() else "_" for c in result['target'])[:40]
            output_path = str(Config.REPORTS_DIR / f"nexus_{safe_target}.html")

        target = result['target']
        risk = result['risk']
        findings = result.get('findings', {})
        graph_json = json.dumps(graph.to_dict(), ensure_ascii=False)
        rc = RISK_COLOR.get(risk['level'], '#607D8B')

        findings_html = self._findings_to_html(findings)
        factors_html = (
            ''.join(f"<li>{html_lib.escape(f)}</li>" for f in risk.get('factors', []))
            or "<li>Nenhum fator de risco crítico identificado</li>"
        )

        content = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEXUS — {html_lib.escape(target)} | Mão de Deus v{VERSION}</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
:root{{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--dim:#8b949e;--accent:#58a6ff;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif}}
.hdr{{background:linear-gradient(135deg,#0d1117,#161b22,#1c2128);border-bottom:1px solid var(--border);padding:22px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}}
.logo{{font-size:1.4em;font-weight:700;color:#58a6ff;letter-spacing:3px}}.logo span{{color:#f85149}}
.sub{{color:var(--dim);font-size:.82em;margin-top:3px}}
.meta{{margin-top:8px;color:var(--dim);font-size:.82em}}
.meta strong{{color:var(--text)}}
.rbadge{{display:inline-flex;align-items:center;gap:6px;padding:8px 18px;border-radius:18px;font-weight:700;background:{rc}22;border:2px solid {rc};color:{rc};font-size:1em}}
.wrap{{max-width:1600px;margin:0 auto;padding:22px 32px}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:20px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px}}
.card h3{{color:var(--accent);font-size:.82em;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}}
.sv{{font-size:1.9em;font-weight:700}}.sl{{color:var(--dim);font-size:.78em;margin-top:3px}}
.gsec{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:20px}}
.ghdr{{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}}
.ghdr h2{{font-size:.95em}}
#gc{{width:100%;height:580px;border-radius:8px;background:#070c12;overflow:hidden;position:relative}}
.tip{{position:fixed;background:#1c2128;border:1px solid var(--border);border-radius:8px;padding:10px 14px;font-size:.78em;pointer-events:none;box-shadow:0 8px 24px #0009;max-width:280px;z-index:999;display:none}}
.ctrls{{position:absolute;top:8px;right:8px;display:flex;gap:5px;z-index:10}}
.btn{{background:#1c2128;border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:5px;cursor:pointer;font-size:.78em}}.btn:hover{{background:var(--border)}}
.srch{{background:#070c12;border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:5px;font-size:.8em;width:180px}}.srch:focus{{outline:none;border-color:var(--accent)}}
.leg{{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}}
.li{{display:flex;align-items:center;gap:4px;font-size:.72em;color:var(--dim)}}
.ld{{width:9px;height:9px;border-radius:50%}}
.fsec{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:20px}}
.fsec h2{{font-size:.95em;margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:8px}}
.fg{{margin-bottom:14px}}.fg h4{{color:var(--accent);font-size:.82em;margin-bottom:6px}}
.fi{{background:#0d1117;border:1px solid var(--border);border-radius:5px;padding:7px 10px;margin-bottom:3px;font-size:.79em;color:var(--dim)}}
.fi .k{{color:var(--text);font-weight:600;margin-right:5px}}
.rf ul{{list-style:none}}.rf li{{padding:5px 0;border-bottom:1px solid var(--border);font-size:.82em;color:var(--dim)}}.rf li::before{{content:'\\26A0 ';color:#d29922}}
footer{{text-align:center;color:var(--dim);font-size:.72em;padding:20px;border-top:1px solid var(--border);margin-top:20px}}
</style>
</head>
<body>
<header class="hdr">
  <div>
    <div class="logo">NEXUS<span>.</span>ENGINE</div>
    <div class="sub">Mão de Deus UNIFIED v{VERSION} &mdash; Motor de Correlação de Inteligência</div>
    <div class="meta">
      Alvo: <strong>{html_lib.escape(target)}</strong> &nbsp;|&nbsp;
      Tipo: <strong style="color:var(--accent)">{result.get('target_type', '?').upper()}</strong> &nbsp;|&nbsp;
      Módulos: <strong>{len(findings)}</strong> &nbsp;|&nbsp;
      Tempo: <strong>{result.get('elapsed_s', '?')}s</strong>
    </div>
  </div>
  <div class="rbadge">RISCO {risk['level']} &mdash; {risk['score']}/100</div>
</header>

<div class="wrap">
  <div class="grid">
    <div class="card">
      <h3>Score de Risco</h3>
      <div class="sv" style="color:{rc}">{risk['score']}<span style="font-size:.45em;color:var(--dim)">/100</span></div>
      <div class="sl">Nível: {risk['level']}</div>
    </div>
    <div class="card">
      <h3>Entidades no Grafo</h3>
      <div class="sv">{risk.get('node_count', 0)}</div>
      <div class="sl">{risk.get('edge_count', 0)} conexões mapeadas</div>
    </div>
    <div class="card">
      <h3>Módulos Executados</h3>
      <div class="sv">{len(findings)}</div>
      <div class="sl">em paralelo &mdash; {result.get('elapsed_s', '?')}s total</div>
    </div>
  </div>

  <div class="gsec">
    <div class="ghdr">
      <h2>Grafo de Inteligência OSINT &mdash; {html_lib.escape(target)}</h2>
      <input class="srch" id="srch" placeholder="Buscar nó..." oninput="filterNodes(this.value)">
    </div>
    <div class="leg">
      <div class="li"><div class="ld" style="background:#4FC3F7"></div>Domínio</div>
      <div class="li"><div class="ld" style="background:#42A5F5"></div>Subdomínio</div>
      <div class="li"><div class="ld" style="background:#EF5350"></div>IP</div>
      <div class="li"><div class="ld" style="background:#66BB6A"></div>Email</div>
      <div class="li"><div class="ld" style="background:#FFA726"></div>Org</div>
      <div class="li"><div class="ld" style="background:#FFCA28"></div>Tech</div>
      <div class="li"><div class="ld" style="background:#9CCC65"></div>URL/Porta</div>
      <div class="li"><div class="ld" style="background:#F44336"></div>Ameaça</div>
    </div>
    <div style="position:relative;margin-top:12px">
      <div id="gc"></div>
      <div class="ctrls">
        <button class="btn" onclick="resetZoom()">Reset</button>
        <button class="btn" onclick="toggleLabels()">Labels</button>
        <button class="btn" onclick="reheat()">Reheat</button>
      </div>
    </div>
  </div>

  <div class="fsec rf">
    <h2>Fatores de Risco</h2>
    <ul>{factors_html}</ul>
  </div>

  <div class="fsec">
    <h2>Inteligência Coletada</h2>
    {findings_html}
  </div>
</div>

<footer>NEXUS Engine &mdash; Mão de Deus UNIFIED v{VERSION}</footer>

<div class="tip" id="tip"></div>

<script>
const G = {graph_json};
const W = document.getElementById('gc').clientWidth;
const H = 580;
const svg = d3.select('#gc').append('svg').attr('width',W).attr('height',H);
const g   = svg.append('g');
let showL = true;

const zoom = d3.zoom().scaleExtent([.08,10]).on('zoom', e=>g.attr('transform',e.transform));
svg.call(zoom);

const defs = svg.append('defs');
defs.append('marker').attr('id','arr').attr('viewBox','0 -5 10 10')
  .attr('refX',22).attr('refY',0).attr('markerWidth',5).attr('markerHeight',5)
  .attr('orient','auto').append('path').attr('d','M0,-5L10,0L0,5').attr('fill','#444');

const sim = d3.forceSimulation(G.nodes)
  .force('link',  d3.forceLink(G.edges).id(d=>d.id).distance(130).strength(.6))
  .force('charge',d3.forceManyBody().strength(-350))
  .force('center',d3.forceCenter(W/2,H/2))
  .force('collide',d3.forceCollide(28));

const link = g.append('g').selectAll('line').data(G.edges).join('line')
  .attr('stroke','#2a3040').attr('stroke-width',1.2).attr('marker-end','url(#arr)');

const llbl = g.append('g').selectAll('text').data(G.edges).join('text')
  .attr('fill','#3a4050').attr('font-size','8px').attr('text-anchor','middle')
  .text(d=>d.label||'');

const node = g.append('g').selectAll('circle').data(G.nodes).join('circle')
  .attr('r',d=>d.id===G.nodes[0]?.id?20:(d.risk>65?14:10))
  .attr('fill',d=>d.color)
  .attr('stroke',d=>d.risk>70?'#F44336':'#2a3040')
  .attr('stroke-width',d=>d.risk>70?2.5:1)
  .style('cursor','pointer')
  .call(d3.drag().on('start',ds).on('drag',dd).on('end',de))
  .on('mousemove',showTip).on('mouseleave',hideTip).on('click',nc);

const lbl = g.append('g').selectAll('text').data(G.nodes).join('text')
  .attr('fill','#b0bcc8').attr('font-size','10px').attr('dx',13).attr('dy',4)
  .text(d=>d.label.substring(0,32));

sim.on('tick',()=>{{
  link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
      .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
  llbl.attr('x',d=>(d.source.x+d.target.x)/2).attr('y',d=>(d.source.y+d.target.y)/2);
  node.attr('cx',d=>d.x).attr('cy',d=>d.y);
  lbl.attr('x',d=>d.x).attr('y',d=>d.y);
}});

function ds(e,d){{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y}}
function dd(e,d){{d.fx=e.x;d.fy=e.y}}
function de(e,d){{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}}
function reheat(){{sim.alpha(.5).restart()}}

function showTip(e,d){{
  const t=document.getElementById('tip');
  const rc=d.risk>70?'#f85149':d.risk>40?'#d29922':'#3fb950';
  t.innerHTML=`<div style="font-weight:700;color:#e6edf3;margin-bottom:5px">${{d.label}}</div>
    <div style="color:#8b949e">Tipo: <span style="color:#58a6ff">${{d.type}}</span></div>
    <div style="color:#8b949e">Risco: <span style="color:${{rc}};font-weight:600">${{d.risk}}/100</span></div>`;
  t.style.display='block';t.style.left=(e.clientX+15)+'px';t.style.top=(e.clientY-10)+'px';
}}
function hideTip(){{document.getElementById('tip').style.display='none'}}
function nc(e,d){{
  node.attr('stroke',n=>n.risk>70?'#F44336':'#2a3040').attr('stroke-width',n=>n.risk>70?2.5:1);
  d3.select(this).attr('stroke','#58a6ff').attr('stroke-width',3);
}}
function resetZoom(){{svg.transition().duration(400).call(zoom.transform,d3.zoomIdentity.translate(W/2,H/2).scale(.8).translate(-W/2,-H/2))}}
function toggleLabels(){{showL=!showL;lbl.style('display',showL?'':'none');llbl.style('display',showL?'':'none')}}
function filterNodes(q){{
  if(!q){{node.attr('opacity',1);lbl.attr('opacity',1);return}}
  const ql=q.toLowerCase();
  node.attr('opacity',d=>d.label.toLowerCase().includes(ql)||d.id.toLowerCase().includes(ql)?1:.1);
  lbl.attr('opacity',d=>d.label.toLowerCase().includes(ql)?1:.08);
}}
</script>
</body>
</html>"""

        Path(output_path).parent.mkdir(exist_ok=True, parents=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return output_path

    def _findings_to_html(self, findings: Dict[str, Any]) -> str:
        sections = []

        def _v(obj):
            if isinstance(obj, bool):
                return f'<span class="fi">{"Sim" if obj else "Não"}</span>'
            if isinstance(obj, list):
                if not obj:
                    return '<em style="color:var(--dim)">vazio</em>'
                inner = ''.join(f'<div class="fi">{_v(i)}</div>' for i in obj[:10])
                more = f'<div class="fi" style="color:var(--dim)">+{len(obj) - 10} itens</div>' if len(obj) > 10 else ''
                return inner + more
            if isinstance(obj, dict):
                rows = ''.join(
                    f'<div class="fi"><span class="k">{html_lib.escape(str(k))}:</span>{_v(v)}</div>'
                    for k, v in list(obj.items())[:15] if not str(k).startswith('_')
                )
                return rows or '<em style="color:var(--dim)">vazio</em>'
            if obj is None:
                return '<span style="color:var(--dim)">N/A</span>'
            s = str(obj)
            if s.startswith('http'):
                return f'<a href="{html_lib.escape(s)}" target="_blank" style="color:#58a6ff">{html_lib.escape(s[:80])}</a>'
            return html_lib.escape(s[:200])

        for name, data in findings.items():
            if not data:
                continue
            sections.append(f'<div class="fg"><h4>{html_lib.escape(str(name))}</h4>{_v(data)}</div>')

        return '\n'.join(sections) if sections else '<p style="color:var(--dim)">Sem dados coletados.</p>'
