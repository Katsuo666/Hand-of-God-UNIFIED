# -*- coding: utf-8 -*-
"""Testes de reports/: geração dos 6 formatos em disco. Sem rede."""

import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from reports import NexusReporter, ReportGenerator
from modules.intelligence import IntelGraph


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.rg = ReportGenerator(output_dir=self.tmp_dir)
        self.data = {
            'target': 'example.com',
            'findings': {'dns': {'A': ['1.2.3.4']}, 'subdomains': ['www.example.com']},
            'risk': {'score': 42, 'level': 'MÉDIO'},
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_json(self):
        path = self.rg.generate(self.data, 'json', filename='t')
        self.assertTrue(Path(path).exists())
        import json
        with open(path, encoding='utf-8') as f:
            loaded = json.load(f)
        self.assertEqual(loaded['target'], 'example.com')

    def test_csv(self):
        path = self.rg.generate([self.data], 'csv', filename='t')
        self.assertTrue(Path(path).exists())

    def test_html(self):
        path = self.rg.generate(self.data, 'html', filename='t')
        content = Path(path).read_text(encoding='utf-8')
        self.assertIn('<html', content)
        self.assertIn('example.com', content)

    def test_xml_valido(self):
        path = self.rg.generate(self.data, 'xml', filename='t')
        ET.parse(path)  # levanta exceção se XML for inválido

    def test_markdown(self):
        path = self.rg.generate(self.data, 'markdown', filename='t')
        content = Path(path).read_text(encoding='utf-8')
        self.assertTrue(content.startswith('#'))

    def test_text(self):
        path = self.rg.generate(self.data, 'text', filename='t')
        self.assertTrue(Path(path).exists())

    def test_formato_desconhecido_cai_para_texto(self):
        path = self.rg.generate(self.data, 'formato-invalido', filename='t')
        self.assertTrue(path.endswith('.txt'))


class TestNexusReporter(unittest.TestCase):
    def test_gera_dashboard_com_grafo(self):
        tmp_dir = tempfile.mkdtemp()
        try:
            g = IntelGraph()
            cid = g.add_node('example.com', 'domain', 'example.com')
            g.set_risk(cid, 40)
            result = {
                'target': 'example.com', 'target_type': 'domain', 'elapsed_s': 1.0,
                'findings': {}, 'risk': {'score': 40, 'level': 'MÉDIO', 'factors': [],
                                          'node_count': 1, 'edge_count': 0},
            }
            output_path = str(Path(tmp_dir) / 'dash.html')
            path = NexusReporter().generate_dashboard(result, g, output_path)
            content = Path(path).read_text(encoding='utf-8')
            self.assertIn('d3js.org', content)
            self.assertIn('example.com', content)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
