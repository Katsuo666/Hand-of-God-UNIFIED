# -*- coding: utf-8 -*-
"""Testes de modules/ai/: SecretScanner (estático) e ExploitTester (payloads, HTTP mockado). Sem rede."""

import unittest
from unittest.mock import MagicMock

from modules.ai import ExploitTester, SecretScanner


class FakeResponse:
    def __init__(self, text='', status_code=200):
        self.text = text
        self.status_code = status_code


class TestSecretScanner(unittest.TestCase):
    def test_detecta_aws_key(self):
        html = 'const key = "AKIAABCDEFGHIJKLMNOP";'
        result = SecretScanner().scan(html, 'https://example.com')
        types = [s['type'] for s in result['secrets']]
        self.assertIn('AWS Access Key ID', types)

    def test_sem_secrets(self):
        result = SecretScanner().scan('<html>nada aqui</html>', 'https://example.com')
        self.assertEqual(result['secrets'], [])

    def test_detecta_tecnologia(self):
        result = SecretScanner().scan('<html>wp-content/plugins/foo</html>', 'https://example.com')
        self.assertIn('WordPress', result['stack'])


class TestExploitTester(unittest.TestCase):
    def test_detecta_xss_refletido(self):
        fake_client = MagicMock()
        fake_client.get.side_effect = lambda url, params=None, **kw: FakeResponse(
            f"echo: {list(params.values())[0]}" if params else ""
        )
        fake_client.post.side_effect = fake_client.get.side_effect

        tester = ExploitTester('https://vulneravel.test/search?q=x', http_client=fake_client, max_params=1)
        result = tester.scan()
        self.assertTrue(result.success)
        self.assertTrue(any(f.type == 'XSS_REFLECTED' for f in result.findings))

    def test_detecta_sqli_error_based(self):
        fake_client = MagicMock()

        def fake_get(url, params=None, **kw):
            payload = list(params.values())[0] if params else ''
            if 'extractvalue' in payload:
                return FakeResponse('mysql_fetch_array() warning near syntax')
            return FakeResponse('ok')

        fake_client.get.side_effect = fake_get
        fake_client.post.side_effect = fake_get

        tester = ExploitTester('https://vulneravel.test/item?id=1', http_client=fake_client, max_params=1)
        result = tester.scan()
        self.assertTrue(any(f.type == 'SQLI_ERROR_BASED' for f in result.findings))

    def test_alvo_seguro_sem_findings(self):
        fake_client = MagicMock()
        fake_client.get.return_value = FakeResponse('nada aqui')
        fake_client.post.return_value = FakeResponse('nada aqui')

        tester = ExploitTester('https://seguro.test/', http_client=fake_client, max_params=2)
        result = tester.scan()
        self.assertTrue(result.success)
        self.assertEqual(result.findings, [])

    def test_ssrf_ignorado_fora_da_whitelist_de_params(self):
        fake_client = MagicMock()
        fake_client.get.return_value = FakeResponse('ok', status_code=200)
        fake_client.post.return_value = FakeResponse('ok', status_code=200)

        # "q" não está em SSRF_TARGET_PARAMS, então SSRF não deve ser testado nele
        tester = ExploitTester('https://exemplo.test/search?q=x', http_client=fake_client, max_params=1)
        result = tester.scan()
        self.assertFalse(any(f.type == 'SSRF_POSSIBLE' for f in result.findings))


if __name__ == '__main__':
    unittest.main()
