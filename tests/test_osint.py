# -*- coding: utf-8 -*-
"""Testes de modules/osint/: orquestradores que não dependem de rede."""

import unittest

from modules.osint import PersonOSSINT, PhoneOSSINT


class TestPersonOSSINT(unittest.TestCase):
    def test_gera_usernames_e_links(self):
        result = PersonOSSINT().analyze('Joao Silva', location='Sao Paulo')
        self.assertEqual(result['type'], 'person')
        self.assertIn('joaosilva', result['possible_usernames'])
        self.assertIn('LinkedIn', result['social_links'])
        self.assertIn('Google+Location', result['search_engines'])

    def test_sem_location(self):
        result = PersonOSSINT().analyze('Maria')
        self.assertIsNone(result['location_hint'])
        self.assertNotIn('Google+Location', result['search_engines'])


class TestPhoneOSSINT(unittest.TestCase):
    def test_telefone_valido_br(self):
        result = PhoneOSSINT().analyze('+5511987654321')
        self.assertTrue(result['valid'])
        self.assertEqual(result['country_code'], 'BR')
        self.assertIn('WhatsApp', result['social_search'])

    def test_telefone_invalido(self):
        result = PhoneOSSINT().analyze('123')
        self.assertFalse(result['valid'])
        self.assertIn('error', result)


if __name__ == '__main__':
    unittest.main()
