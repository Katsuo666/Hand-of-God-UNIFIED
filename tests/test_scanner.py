# -*- coding: utf-8 -*-
"""Testes de modules/scanner/: dataclasses e detecção de WAF com HTTP mockado. Sem rede."""

import unittest
from unittest.mock import MagicMock

from modules.scanner import Finding, ScanResult, WAFDetector


class FakeResponse:
    def __init__(self, headers=None, status_code=200, text=''):
        self.headers = headers or {}
        self.status_code = status_code
        self.text = text


class TestFinding(unittest.TestCase):
    def test_to_dict_preenche_timestamp(self):
        f = Finding(
            type='TEST', severity='LOW', title='t', description='d',
            details={}, evidence=[], remediation='r',
        )
        self.assertIsNotNone(f.timestamp)
        self.assertEqual(f.to_dict()['type'], 'TEST')


class TestScanResult(unittest.TestCase):
    def test_to_dict_serializa_findings(self):
        f = Finding(type='T', severity='LOW', title='t', description='d',
                    details={}, evidence=[], remediation='r')
        result = ScanResult(scanner_name='X', target='y', findings=[f],
                             execution_time=0.1, success=True)
        d = result.to_dict()
        self.assertEqual(len(d['findings']), 1)
        self.assertTrue(d['success'])


class TestWAFDetector(unittest.TestCase):
    def test_detecta_cloudflare_por_header(self):
        fake_client = MagicMock()
        fake_client.get.return_value = FakeResponse(
            headers={'CF-RAY': '123abc', 'Server': 'cloudflare'},
        )
        detector = WAFDetector('https://example.com', http_client=fake_client, cache=MagicMock())
        result = detector.detect_waf_headers()
        self.assertIn('cloudflare', result)

    def test_sem_resposta_retorna_vazio(self):
        fake_client = MagicMock()
        fake_client.get.return_value = None
        detector = WAFDetector('https://example.com', http_client=fake_client, cache=MagicMock())
        result = detector.detect_waf_headers()
        self.assertEqual(result, {})

    def test_sem_waf_nao_detecta_nada(self):
        fake_client = MagicMock()
        fake_client.get.return_value = FakeResponse(headers={'Server': 'nginx'})
        detector = WAFDetector('https://example.com', http_client=fake_client, cache=MagicMock())
        result = detector.detect_waf_headers()
        self.assertEqual(result, {})


if __name__ == '__main__':
    unittest.main()
