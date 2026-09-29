# -*- coding: utf-8 -*-
"""
Orquestrador OSINT de telefone.

Camadas de dados, da mais para a menos fiável/gratuita:
1. phonenumbers (libphonenumber do Google, offline, sem API key): validação real,
   operadora conhecida por range, tipo de linha (móvel/fixo/VOIP/premium/toll-free),
   região geográfica aproximada e timezone.
2. Twilio Lookup v2 (opcional, precisa de conta — tem crédito de trial grátis):
   nome do titular ("caller name", só EUA) e deteção de SIM swap recente —
   é literalmente a mesma base de dados que serviços como o NumberClarify usam.
3. Links de verificação manual (WhatsApp/Telegram/TrueCaller) — não confirmam
   programaticamente se o número está registado nesses serviços (isso violaria os
   termos de uso deles), servem só de atalho para verificação humana.

Não existe nenhuma API gratuita e fiável que devolva "nome do dono" ou
"probabilidade de fraude" de um número — quem promete isso de graça normalmente
está a vender os teus dados. O sinal de risco abaixo é uma heurística honesta
baseada no TIPO de linha (VOIP/premium/toll-free têm taxa de robocall/fraude
muito mais alta), não uma pontuação de fraude real.
"""

from datetime import datetime
from typing import Any, Dict

import phonenumbers
from phonenumbers import carrier as pn_carrier, geocoder as pn_geocoder, timezone as pn_timezone

from core.config import Config
from core.logger import get_logger
from modules.localization.phone_validators import PhoneValidator

logger = get_logger(__name__)

# Tipos de linha com taxa de robocall/fraude historicamente mais alta (FTC/FCC reports)
_HIGH_RISK_TYPES = {
    phonenumbers.PhoneNumberType.VOIP,
    phonenumbers.PhoneNumberType.TOLL_FREE,
    phonenumbers.PhoneNumberType.PREMIUM_RATE,
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER,
}

_TYPE_NAMES = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixo",
    phonenumbers.PhoneNumberType.MOBILE: "móvel",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixo ou móvel",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll-free (0800/linha grátis)",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "tarifa premium",
    phonenumbers.PhoneNumberType.SHARED_COST: "custo partilhado",
    phonenumbers.PhoneNumberType.VOIP: "VOIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "número pessoal",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "UAN",
    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "desconhecido",
}


class PhoneOSSINT:
    def __init__(self):
        self.validator = PhoneValidator()

    def analyze(self, phone: str) -> Dict[str, Any]:
        validation = self.validator.validate(phone)

        result: Dict[str, Any] = {
            "target": phone,
            "type": "phone",
            "timestamp": datetime.now().isoformat(),
            "country_code": validation["country_code"],
            "country_name": validation["country_name"],
            "valid": validation["valid"],
            "normalized_e164": validation["normalized_e164"],
            "social_search": {},
        }

        if not validation["valid"]:
            result["error"] = f"Telefone inválido para {validation['country_name']}"
            return result

        result["carrier_intel"] = self._carrier_intel(validation["normalized_e164"])
        result["twilio_lookup"] = self._twilio_lookup(validation["normalized_e164"])

        safe_phone = validation["normalized_e164"].replace("+", "")
        result["social_search"] = {
            "WhatsApp": f"https://wa.me/{safe_phone}",
            "Telegram": f"https://t.me/{safe_phone}",
            "TrueCaller": f"https://www.truecaller.com/search/{validation['country_code'].lower()}/{safe_phone}",
        }
        result["social_search_note"] = (
            "Estes links são para verificação manual — não é possível confirmar "
            "programaticamente se um número está registado nestes serviços sem violar os seus termos de uso."
        )

        return result

    @staticmethod
    def _carrier_intel(e164: str) -> Dict[str, Any]:
        """Dados offline via libphonenumber: sempre disponível, sem API key."""
        try:
            parsed = phonenumbers.parse(e164, None)
            number_type = phonenumbers.number_type(parsed)
            tzs = pn_timezone.time_zones_for_number(parsed)

            return {
                "carrier": pn_carrier.name_for_number(parsed, "pt") or pn_carrier.name_for_number(parsed, "en") or None,
                "region": pn_geocoder.description_for_number(parsed, "pt") or pn_geocoder.description_for_number(parsed, "en"),
                "line_type": _TYPE_NAMES.get(number_type, "desconhecido"),
                "timezone": list(tzs) if tzs else [],
                "spam_risk": "elevado" if number_type in _HIGH_RISK_TYPES else "baixo",
                "spam_risk_reason": (
                    "Linhas VOIP/toll-free/tarifa-premium têm taxa de robocall e fraude "
                    "historicamente mais alta (heurística por tipo de linha, não uma verificação real do número)."
                    if number_type in _HIGH_RISK_TYPES else None
                ),
            }
        except Exception as e:
            logger.debug(f"Erro no carrier intel para {e164}: {e}")
            return {"error": str(e)}

    @staticmethod
    def _twilio_lookup(e164: str) -> Dict[str, Any]:
        """Nome do titular (só EUA) + deteção de SIM swap via Twilio Lookup v2. Requer conta."""
        if not (Config.TWILIO_ACCOUNT_SID and Config.TWILIO_AUTH_TOKEN):
            return {
                "available": False,
                "hint": "Configura TWILIO_ACCOUNT_SID e TWILIO_AUTH_TOKEN no .env para obter o nome do "
                        "titular (EUA) e deteção de SIM swap — https://console.twilio.com (tem crédito de trial grátis)",
            }

        try:
            from twilio.rest import Client
            client = Client(Config.TWILIO_ACCOUNT_SID, Config.TWILIO_AUTH_TOKEN)
            info = client.lookups.v2.phone_numbers(e164).fetch(
                fields="caller_name,line_type_intelligence,sim_swap"
            )
            return {
                "available": True,
                "caller_name": (info.caller_name or {}).get("caller_name"),
                "caller_type": (info.caller_name or {}).get("caller_type"),
                "line_type_intelligence": info.line_type_intelligence,
                "sim_swap": info.sim_swap,
            }
        except Exception as e:
            logger.debug(f"Erro no Twilio Lookup para {e164}: {e}")
            return {"available": False, "error": str(e)}
