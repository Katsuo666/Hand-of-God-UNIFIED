# -*- coding: utf-8 -*-
"""Grafo de conhecimento OSINT — nós e arestas de relacionamento, pronto para D3.js."""

import re
from typing import Any, Dict, List, Optional


class IntelGraph:
    """Grafo de conhecimento OSINT — nós e arestas de relacionamento."""

    NODE_COLORS = {
        'domain': '#4FC3F7',
        'subdomain': '#42A5F5',
        'ip': '#EF5350',
        'email': '#66BB6A',
        'org': '#FFA726',
        'asn': '#AB47BC',
        'cve': '#FF7043',
        'hash': '#26C6DA',
        'person': '#EC407A',
        'url': '#9CCC65',
        'threat': '#F44336',
        'technology': '#FFCA28',
        'leak': '#EF5350',
        'default': '#78909C',
    }

    def __init__(self):
        self.nodes: Dict[str, dict] = {}
        self.edges: List[dict] = []

    def _nid(self, raw: str) -> str:
        return re.sub(r'[^a-zA-Z0-9_\-]', '_', str(raw))[:80]

    def add_node(self, node_id: str, node_type: str, label: str,
                 data: Optional[dict] = None, risk: int = 0) -> str:
        nid = self._nid(node_id)
        if nid not in self.nodes:
            self.nodes[nid] = {
                'id': nid,
                'label': label[:50],
                'type': node_type,
                'color': self.NODE_COLORS.get(node_type, self.NODE_COLORS['default']),
                'risk': risk,
                'data': data or {},
            }
        return nid

    def add_edge(self, from_id: str, to_id: str, label: str = '', weight: int = 1) -> None:
        fid = self._nid(from_id)
        tid = self._nid(to_id)
        if fid in self.nodes and tid in self.nodes and fid != tid:
            self.edges.append({'from': fid, 'to': tid, 'label': label, 'weight': weight})

    def set_risk(self, node_id: str, risk: int) -> None:
        nid = self._nid(node_id)
        if nid in self.nodes:
            self.nodes[nid]['risk'] = max(self.nodes[nid].get('risk', 0), risk)

    def to_dict(self) -> Dict[str, Any]:
        return {'nodes': list(self.nodes.values()), 'edges': self.edges}
