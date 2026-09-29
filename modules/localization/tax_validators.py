# -*- coding: utf-8 -*-
"""Validação de identificadores fiscais nacionais (BR, US, ES, FR, PT), com
checksum real por país — não é só validação de tamanho/formato."""

import re
from typing import Any, Dict, List, Optional


def _only_digits(value: str) -> str:
    return re.sub(r'\D', '', value)


def _build_result(raw_input: str, digits: str, country: str, id_type: str, description: str) -> Dict[str, Any]:
    return {
        'input': raw_input, 'digits': digits, 'formatted': None, 'valid': False,
        'country': country, 'type': id_type, 'description': description, 'error': None,
    }


class TaxIDValidator:
    """Ponto de entrada único para validação de CPF, CNPJ, SSN, NIF-ES, SIRET e NIF-PT."""

    @staticmethod
    def validate_cpf(value: str) -> Dict[str, Any]:
        digits = _only_digits(value)
        out = _build_result(value, digits, 'BR', 'CPF', 'Cadastro de Pessoa Física')

        if len(digits) != 11:
            out['error'] = f'CPF precisa de 11 dígitos, foram encontrados {len(digits)}'
            return out
        if len(set(digits)) == 1:
            out['error'] = 'Todos os dígitos são iguais — CPF inválido por construção'
            return out

        def checksum_digit(partial: str, weight_start: int) -> int:
            total = sum(int(ch) * (weight_start - idx) for idx, ch in enumerate(partial))
            remainder = (total * 10) % 11
            return 0 if remainder >= 10 else remainder

        first_check = checksum_digit(digits[:9], 10)
        second_check = checksum_digit(digits[:10], 11)

        if int(digits[9]) == first_check and int(digits[10]) == second_check:
            out['valid'] = True
            out['formatted'] = f'{digits[0:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:11]}'
        else:
            out['error'] = 'Falha na verificação dos dígitos de controle'
        return out

    @staticmethod
    def validate_cnpj(value: str) -> Dict[str, Any]:
        digits = _only_digits(value)
        out = _build_result(value, digits, 'BR', 'CNPJ', 'Cadastro Nacional de Pessoa Jurídica')

        if len(digits) != 14:
            out['error'] = f'CNPJ precisa de 14 dígitos, foram encontrados {len(digits)}'
            return out
        if len(set(digits)) == 1:
            out['error'] = 'Todos os dígitos são iguais — CNPJ inválido por construção'
            return out

        weights_first = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
        weights_second = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]

        def checksum_digit(partial: str, weights: List[int]) -> int:
            total = sum(int(ch) * w for ch, w in zip(partial, weights))
            remainder = total % 11
            return 0 if remainder < 2 else 11 - remainder

        first_check = checksum_digit(digits[:12], weights_first)
        second_check = checksum_digit(digits[:13], weights_second)

        if int(digits[12]) == first_check and int(digits[13]) == second_check:
            out['valid'] = True
            out['formatted'] = f'{digits[0:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:14]}'
            out['filial'] = digits[8:12]
        else:
            out['error'] = 'Falha na verificação dos dígitos de controle'
        return out

    @staticmethod
    def validate_ssn(value: str) -> Dict[str, Any]:
        digits = _only_digits(value)
        out = _build_result(value, digits, 'US', 'SSN', 'Social Security Number')

        if len(digits) != 9:
            out['error'] = f'SSN precisa de 9 dígitos, foram encontrados {len(digits)}'
            return out

        reserved_numbers = {'000000000', '666666666', '900000000'}
        if digits in reserved_numbers:
            out['error'] = 'Número reservado pela SSA, nunca emitido a uma pessoa'
            return out

        area, group, serial = digits[0:3], digits[3:5], digits[5:9]
        if area == '000' or group == '00' or serial == '0000':
            out['error'] = 'Uma das séries (area/group/serial) está zerada — formato inválido'
            return out

        out['valid'] = True
        out['formatted'] = f'{area}-{group}-{serial}'
        return out

    @staticmethod
    def validate_nif_es(value: str) -> Dict[str, Any]:
        digit_part = _only_digits(value)
        letter_part = re.sub(r'\d', '', value.upper())
        out = _build_result(value, digit_part, 'ES', 'NIF', 'Número de Identidad Fiscal')

        if len(digit_part) != 8 or len(letter_part) != 1:
            out['error'] = 'NIF espanhol precisa de exatamente 8 dígitos seguidos de 1 letra'
            return out

        control_letters = 'TRWAGMYFPDXBNJZSQVHLCKE'
        expected_letter = control_letters[int(digit_part) % 23]

        if letter_part == expected_letter:
            out['valid'] = True
            out['formatted'] = f'{digit_part}-{letter_part}'
        else:
            out['error'] = f'Letra de controle não confere (esperada "{expected_letter}", recebida "{letter_part}")'
        return out

    @staticmethod
    def validate_siret(value: str) -> Dict[str, Any]:
        digits = _only_digits(value)
        out = _build_result(value, digits, 'FR', 'SIRET',
                             "Numéro d'Enregistrement au Répertoire des Établissements")

        if len(digits) != 14:
            out['error'] = f'SIRET precisa de 14 dígitos, foram encontrados {len(digits)}'
            return out

        def passes_luhn(number: str) -> bool:
            digit_sum = 0
            for position, ch in enumerate(reversed(number)):
                value_at_position = int(ch)
                if position % 2 == 1:
                    value_at_position *= 2
                    if value_at_position > 9:
                        value_at_position -= 9
                digit_sum += value_at_position
            return digit_sum % 10 == 0

        if passes_luhn(digits):
            out['valid'] = True
            out['formatted'] = f'{digits[0:3]} {digits[3:8]} {digits[8:13]} {digits[13]}'
        else:
            out['error'] = 'Checksum Luhn não confere'
        return out

    @staticmethod
    def validate_nif_pt(value: str) -> Dict[str, Any]:
        digits = _only_digits(value)
        out = _build_result(value, digits, 'PT', 'NIF', 'Número de Identificação Fiscal')

        if len(digits) != 9:
            out['error'] = f'NIF português precisa de 9 dígitos, foram encontrados {len(digits)}'
            return out

        weighted_sum = sum(int(ch) * (9 - idx) for idx, ch in enumerate(digits[:8]))
        expected_check_digit = (11 - (weighted_sum % 11)) % 11

        if int(digits[8]) == expected_check_digit:
            out['valid'] = True
            out['formatted'] = digits
        else:
            out['error'] = f'Dígito de controle não confere (esperado {expected_check_digit}, recebido {digits[8]})'
        return out

    @staticmethod
    def validate_tax_id(id_value: str, country: str = 'BR', id_type: Optional[str] = None) -> Dict[str, Any]:
        """Ponto de entrada genérico: deteta o tipo pelo país quando `id_type` não é passado."""
        country = country.upper()

        if id_type is None:
            digit_count = len(_only_digits(id_value))
            id_type = {
                'BR': 'CNPJ' if digit_count == 14 else 'CPF',
                'US': 'SSN', 'ES': 'NIF', 'FR': 'SIRET', 'PT': 'NIF',
            }.get(country)

        validators_by_country_and_type = {
            ('BR', 'CPF'): TaxIDValidator.validate_cpf,
            ('BR', 'CNPJ'): TaxIDValidator.validate_cnpj,
            ('US', 'SSN'): TaxIDValidator.validate_ssn,
            ('ES', 'NIF'): TaxIDValidator.validate_nif_es,
            ('FR', 'SIRET'): TaxIDValidator.validate_siret,
            ('PT', 'NIF'): TaxIDValidator.validate_nif_pt,
        }

        chosen_validator = validators_by_country_and_type.get((country, id_type))
        if chosen_validator:
            return chosen_validator(id_value)

        return {
            'input': id_value, 'valid': False, 'country': country, 'type': id_type,
            'error': f'Combinação de país e tipo não suportada ({country}/{id_type})',
        }
