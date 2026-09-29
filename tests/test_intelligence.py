# -*- coding: utf-8 -*-
"""Testes de modules/intelligence/: IntelGraph, RiskAnalyzer, NexusEngine.detect_type. Sem rede."""

import unittest

from modules.intelligence import IntelGraph, NexusEngine, RiskAnalyzer


class TestIntelGraph(unittest.TestCase):
    def test_add_node_dedup(self):
        g = IntelGraph()
        n1 = g.add_node('example.com', 'domain', 'example.com')
        n2 = g.add_node('example.com', 'domain', 'example.com (dup)')
        self.assertEqual(n1, n2)
        self.assertEqual(len(g.nodes), 1)
        # o label do primeiro add é preservado (nó já existia)
        self.assertEqual(g.nodes[n1]['label'], 'example.com')

    def test_add_edge_ignora_nos_inexistentes(self):
        g = IntelGraph()
        cid = g.add_node('a', 'domain', 'a')
        g.add_edge(cid, 'nao-existe', 'rel')
        self.assertEqual(len(g.edges), 0)

    def test_add_edge_ignora_self_loop(self):
        g = IntelGraph()
        cid = g.add_node('a', 'domain', 'a')
        g.add_edge(cid, cid, 'self')
        self.assertEqual(len(g.edges), 0)

    def test_set_risk_mantem_maximo(self):
        g = IntelGraph()
        cid = g.add_node('a', 'domain', 'a', risk=10)
        g.set_risk('a', 5)
        self.assertEqual(g.nodes[cid]['risk'], 10)
        g.set_risk('a', 90)
        self.assertEqual(g.nodes[cid]['risk'], 90)

    def test_to_dict(self):
        g = IntelGraph()
        cid = g.add_node('a', 'domain', 'a')
        nid = g.add_node('1.2.3.4', 'ip', '1.2.3.4')
        g.add_edge(cid, nid, 'resolve')
        d = g.to_dict()
        self.assertEqual(len(d['nodes']), 2)
        self.assertEqual(len(d['edges']), 1)


class TestRiskAnalyzer(unittest.TestCase):
    def test_sem_fatores_risco_zero(self):
        g = IntelGraph()
        g.add_node('a', 'domain', 'a')
        risk = RiskAnalyzer.analyze({}, {}, g)
        self.assertEqual(risk['score'], 0)
        self.assertEqual(risk['level'], 'BAIXO')

    def test_muitos_subdominios_eleva_risco(self):
        g = IntelGraph()
        g.add_node('a', 'domain', 'a')
        findings = {'passive': {'findings': {'subdomains': [f's{i}' for i in range(60)]}}}
        risk = RiskAnalyzer.analyze(findings, {}, g)
        self.assertGreater(risk['score'], 0)
        self.assertTrue(any('subdomínios' in f for f in risk['factors']))

    def test_indicador_malicioso_eleva_risco(self):
        g = IntelGraph()
        g.add_node('a', 'ip', 'a')
        threat_intel = {'analysis': {'is_malicious': True}}
        risk = RiskAnalyzer.analyze({}, threat_intel, g)
        self.assertGreaterEqual(risk['score'], 70)


class TestNexusEngineDetectType(unittest.TestCase):
    def setUp(self):
        self.nexus = NexusEngine()

    def test_email(self):
        self.assertEqual(self.nexus.detect_type('user@example.com'), 'email')

    def test_ip(self):
        self.assertEqual(self.nexus.detect_type('8.8.8.8'), 'ip')

    def test_url(self):
        self.assertEqual(self.nexus.detect_type('https://example.com'), 'url')

    def test_domain(self):
        self.assertEqual(self.nexus.detect_type('example.com'), 'domain')

    def test_hash(self):
        self.assertEqual(self.nexus.detect_type('44d88612fea8a8f36de82e1278abb02f'), 'hash')

    def test_unknown(self):
        self.assertEqual(self.nexus.detect_type('###nada válido###'), 'unknown')


if __name__ == '__main__':
    unittest.main()
