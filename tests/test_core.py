# -*- coding: utf-8 -*-
"""Testes de core/: Config, Validator, PersistentCache. Sem rede."""

import shutil
import tempfile
import unittest
from pathlib import Path

from core.config import Config
from core.persistent_cache import PersistentCache
from core.validator import Validator


class TestConfig(unittest.TestCase):
    def test_diretorios_existem(self):
        for d in (Config.DATA_DIR, Config.CACHE_DIR, Config.LOGS_DIR, Config.REPORTS_DIR):
            self.assertTrue(Path(d).is_dir(), f"{d} deveria existir")


class TestValidator(unittest.TestCase):
    def test_is_email(self):
        self.assertTrue(Validator.is_email("user@example.com"))
        self.assertFalse(Validator.is_email("not-an-email"))

    def test_is_domain(self):
        self.assertTrue(Validator.is_domain("example.com"))
        self.assertFalse(Validator.is_domain("not a domain"))

    def test_is_ip(self):
        # is_ip valida apenas IPv4 (ver docstring em core/validator.py)
        self.assertTrue(Validator.is_ip("8.8.8.8"))
        self.assertFalse(Validator.is_ip("999.999.999.999"))
        self.assertFalse(Validator.is_ip("::1"))

    def test_is_url(self):
        self.assertTrue(Validator.is_url("https://example.com/path"))
        self.assertFalse(Validator.is_url("ftp:not a url"))

    def test_hash_detection(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertTrue(Validator.is_md5(md5))
        self.assertTrue(Validator.is_sha1(sha1))
        self.assertTrue(Validator.is_sha256(sha256))
        self.assertFalse(Validator.is_md5("nao-e-um-hash"))


class TestPersistentCache(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.cache = PersistentCache(cache_dir=Path(self.tmp_dir), db_name="test_cache.db")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_set_get(self):
        self.cache.set("chave", {"valor": 42}, ttl=60)
        self.assertEqual(self.cache.get("chave"), {"valor": 42})

    def test_get_inexistente(self):
        self.assertIsNone(self.cache.get("nao-existe"))

    def test_delete(self):
        self.cache.set("chave", "x", ttl=60)
        self.cache.delete("chave")
        self.assertIsNone(self.cache.get("chave"))

    def test_exists(self):
        self.cache.set("chave", "x", ttl=60)
        self.assertTrue(self.cache.exists("chave"))
        self.assertFalse(self.cache.exists("outra"))


if __name__ == '__main__':
    unittest.main()
