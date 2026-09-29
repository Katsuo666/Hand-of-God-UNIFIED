# -*- coding: utf-8 -*-
"""Utilitários criptográficos standalone (hash, encode/decode, uuid, rot13, césar)."""

import base64
import codecs
import hashlib
import uuid
from typing import Any, Dict


class CryptoTools:
    """Operações criptográficas simples sobre uma string arbitrária."""

    @staticmethod
    def hash_string(text: str) -> Dict[str, str]:
        data = text.encode("utf-8")
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        }

    @staticmethod
    def encode(text: str, scheme: str) -> str:
        data = text.encode("utf-8")
        if scheme == "base64":
            return base64.b64encode(data).decode()
        if scheme == "hex":
            return data.hex()
        if scheme == "url":
            from urllib.parse import quote
            return quote(text)
        raise ValueError(f"Esquema de encode desconhecido: {scheme}")

    @staticmethod
    def decode(text: str, scheme: str) -> str:
        if scheme == "base64":
            return base64.b64decode(text).decode("utf-8", errors="replace")
        if scheme == "hex":
            return bytes.fromhex(text).decode("utf-8", errors="replace")
        if scheme == "url":
            from urllib.parse import unquote
            return unquote(text)
        raise ValueError(f"Esquema de decode desconhecido: {scheme}")

    @staticmethod
    def generate_uuid() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def rot13(text: str) -> str:
        return codecs.encode(text, "rot_13")

    @staticmethod
    def caesar(text: str, shift: int) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def identify_hash(value: str) -> Dict[str, Any]:
        """Identifica possíveis algoritmos de hash pelo comprimento/formato do valor."""
        value = value.strip()
        length = len(value)
        is_hex = all(c in "0123456789abcdefABCDEF" for c in value)
        candidates = []
        if is_hex:
            by_length = {
                32: ["MD5", "NTLM", "MD4"],
                40: ["SHA1", "RIPEMD-160"],
                56: ["SHA-224"],
                64: ["SHA-256", "SHA3-256"],
                96: ["SHA-384"],
                128: ["SHA-512", "SHA3-512"],
            }
            candidates = by_length.get(length, [])
        elif value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$"):
            candidates = ["bcrypt"]
        elif value.startswith("$1$"):
            candidates = ["MD5 crypt"]
        elif value.startswith("$6$"):
            candidates = ["SHA-512 crypt"]
        return {
            "value": value,
            "length": length,
            "is_hex": is_hex,
            "possible_algorithms": candidates or ["desconhecido"],
        }
