# -*- coding: utf-8 -*-
"""Testes de modules/scanner/http_hardening_scanner.py e injection_scanner.py: HTTP mockado, sem rede."""

import unittest
from unittest.mock import MagicMock

from modules.scanner import (
    SecurityHeadersScanner, CookieSecurityScanner, OpenRedirectScanner,
    DirectoryListingScanner,
)
from modules.scanner.injection_scanner import HTMLInjectionTester, PathTraversalTester


class FakeResponse:
    def __init__(self, headers=None, status_code=200, text='', cookies=None):
        self.headers = headers or {}
        self.status_code = status_code
        self.text = text
        self.cookies = cookies or {}
        self.raw = MagicMock()
        self.raw.headers = MagicMock()
        self.raw.headers.getlist = MagicMock(return_value=None)


class TestSecurityHeadersScanner(unittest.TestCase):
    def test_sinaliza_headers_ausentes(self):
        client = MagicMock()
        client.get.return_value = FakeResponse(headers={'Server': 'nginx/1.18.0'})
        result = SecurityHeadersScanner('http://x', http_client=client).scan()
        types = {f.type for f in result.findings}
        self.assertIn('MISSING_SECURITY_HEADER', types)
        self.assertIn('SERVER_VERSION_DISCLOSURE', types)

    def test_nao_sinaliza_quando_headers_presentes(self):
        client = MagicMock()
        client.get.return_value = FakeResponse(headers={
            'Strict-Transport-Security': 'max-age=1', 'Content-Security-Policy': "default-src 'self'",
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'geolocation=()',
        })
        result = SecurityHeadersScanner('http://x', http_client=client).scan()
        self.assertEqual(result.findings, [])


class TestCookieSecurityScanner(unittest.TestCase):
    def test_sinaliza_cookie_sem_flags(self):
        client = MagicMock()
        client.get.return_value = FakeResponse(headers={'Set-Cookie': 'session=abc'})
        result = CookieSecurityScanner('http://x', http_client=client).scan()
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].type, 'COOKIE_MISSING_FLAGS')

    def test_cookie_com_flags_nao_sinaliza(self):
        client = MagicMock()
        client.get.return_value = FakeResponse(
            headers={'Set-Cookie': 'session=abc; Secure; HttpOnly; SameSite=Strict'})
        result = CookieSecurityScanner('http://x', http_client=client).scan()
        self.assertEqual(result.findings, [])


class TestOpenRedirectScanner(unittest.TestCase):
    def test_detecta_redirect_para_dominio_externo(self):
        client = MagicMock()
        client.get.return_value = FakeResponse(
            status_code=302,
            headers={'Location': 'https://example-external-redirect-test.invalid'},
        )
        result = OpenRedirectScanner('http://x/redirect', http_client=client).scan()
        self.assertTrue(any(f.type == 'OPEN_REDIRECT' for f in result.findings))

    def test_sem_redirect_nao_sinaliza(self):
        client = MagicMock()
        client.get.return_value = FakeResponse(status_code=200)
        result = OpenRedirectScanner('http://x', http_client=client).scan()
        self.assertEqual(result.findings, [])


class TestDirectoryListingScanner(unittest.TestCase):
    def test_detecta_index_of(self):
        client = MagicMock()
        client.get.return_value = FakeResponse(status_code=200, text='<html>Index of /uploads/</html>')
        result = DirectoryListingScanner('http://x', http_client=client).scan()
        self.assertTrue(any(f.type == 'DIRECTORY_LISTING_ENABLED' for f in result.findings))

    def test_sem_listagem_nao_sinaliza(self):
        client = MagicMock()
        client.get.return_value = FakeResponse(status_code=404, text='not found')
        result = DirectoryListingScanner('http://x', http_client=client).scan()
        self.assertEqual(result.findings, [])


class TestHTMLInjectionTester(unittest.TestCase):
    def test_detecta_reflexao_de_html(self):
        client = MagicMock()
        payload = '<b style="color:red">mao-de-deus-htmli-test</b>'
        client.get.return_value = FakeResponse(status_code=200, text=f'<html>{payload}</html>')
        tester = HTMLInjectionTester('http://x?q=1', http_client=client, max_params=1)
        result = tester.scan()
        self.assertTrue(any(f.type == 'HTML_INJECTION' for f in result.findings))


class TestPathTraversalTester(unittest.TestCase):
    def test_detecta_conteudo_de_etc_passwd(self):
        client = MagicMock()
        client.get.return_value = FakeResponse(status_code=200, text='root:x:0:0:root:/root:/bin/bash')
        tester = PathTraversalTester('http://x?file=a', http_client=client, max_params=1)
        result = tester.scan()
        self.assertTrue(any(f.type == 'PATH_TRAVERSAL' for f in result.findings))

    def test_sem_vazamento_nao_sinaliza(self):
        client = MagicMock()
        client.get.return_value = FakeResponse(status_code=404, text='not found')
        tester = PathTraversalTester('http://x?file=a', http_client=client, max_params=1)
        result = tester.scan()
        self.assertEqual(result.findings, [])


if __name__ == '__main__':
    unittest.main()
