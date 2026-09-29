# -*- coding: utf-8 -*-
"""Testes de modules/localization/: CountryRegistry, TaxIDValidator, PhoneValidator. Sem rede."""

import unittest

from modules.localization import (
    CountryRegistry, TaxIDValidator, PhoneValidator, is_disposable_email,
)


class TestCountryRegistry(unittest.TestCase):
    def test_paises_suportados(self):
        registry = CountryRegistry()
        self.assertEqual(set(registry.list_supported()), {'BR', 'US', 'UK', 'ES', 'FR', 'PT'})

    def test_fallback_generic(self):
        registry = CountryRegistry()
        country = registry.get('XX')
        self.assertEqual(country.code, 'GENERIC')

    def test_singleton(self):
        self.assertIs(CountryRegistry(), CountryRegistry())

    def test_detect_country_from_phone(self):
        registry = CountryRegistry()
        self.assertEqual(registry.detect_country_from_phone('+5511987654321'), 'BR')
        self.assertEqual(registry.detect_country_from_phone('+12025551234'), 'US')
        self.assertEqual(registry.detect_country_from_phone('+999999999'), 'GENERIC')


class TestTaxIDValidator(unittest.TestCase):
    def test_cpf_valido(self):
        result = TaxIDValidator.validate_cpf('111.444.777-35')
        self.assertTrue(result['valid'])
        self.assertEqual(result['formatted'], '111.444.777-35')

    def test_cpf_invalido(self):
        result = TaxIDValidator.validate_cpf('111.111.111-11')
        self.assertFalse(result['valid'])

    def test_cnpj_invalido_tamanho(self):
        result = TaxIDValidator.validate_cnpj('123')
        self.assertFalse(result['valid'])
        self.assertIn('14 dígitos', result['error'])

    def test_ssn_reservado(self):
        result = TaxIDValidator.validate_ssn('000000000')
        self.assertFalse(result['valid'])

    def test_nif_pt_checksum_valido(self):
        result = TaxIDValidator.validate_nif_pt('123456789')
        self.assertTrue(result['valid'])

    def test_nif_pt_checksum_invalido(self):
        result = TaxIDValidator.validate_nif_pt('123456780')
        self.assertFalse(result['valid'])

    def test_auto_deteccao_por_pais(self):
        result = TaxIDValidator.validate_tax_id('000000000', country='US')
        self.assertEqual(result['type'], 'SSN')

    def test_combinacao_nao_suportada(self):
        result = TaxIDValidator.validate_tax_id('123', country='DE', id_type='FOO')
        self.assertFalse(result['valid'])
        self.assertIn('não suportada', result['error'])


class TestPhoneValidator(unittest.TestCase):
    def test_valida_e_detecta_pais(self):
        result = PhoneValidator().validate('+5511987654321')
        self.assertEqual(result['country_code'], 'BR')
        self.assertTrue(result['valid'])
        self.assertEqual(result['normalized_e164'], '+5511987654321')

    def test_telefone_invalido(self):
        result = PhoneValidator().validate('123')
        self.assertFalse(result['valid'])


class TestDisposableEmail(unittest.TestCase):
    def test_dominio_descartavel(self):
        self.assertTrue(is_disposable_email('foo@mailinator.com'))

    def test_dominio_normal(self):
        self.assertFalse(is_disposable_email('foo@gmail.com'))

    def test_sem_arroba(self):
        self.assertFalse(is_disposable_email('nao-e-email'))


if __name__ == '__main__':
    unittest.main()
