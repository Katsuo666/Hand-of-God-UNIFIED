# -*- coding: utf-8 -*-
"""Utilitários de segurança local: scan de diretório, hash de ficheiro, permissões, password."""

import hashlib
import os
import secrets
import stat
import string
from datetime import datetime
from typing import Any, Dict, List

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".jar", ".sh",
}
SUSPICIOUS_NAME_HINTS = ("keylogger", "backdoor", "trojan", "ransom", "miner")


class SecurityTools:
    """Operações de segurança sobre o sistema de ficheiros local."""

    @staticmethod
    def scan_directory(path: str, max_files: int = 5000) -> Dict[str, Any]:
        """Procura ficheiros com extensão ou nome potencialmente suspeitos."""
        suspicious: List[Dict[str, Any]] = []
        scanned = 0
        for root, _dirs, files in os.walk(path):
            for name in files:
                if scanned >= max_files:
                    break
                scanned += 1
                full_path = os.path.join(root, name)
                ext = os.path.splitext(name)[1].lower()
                name_lower = name.lower()
                reasons = []
                if ext in SUSPICIOUS_EXTENSIONS:
                    reasons.append(f"extensão {ext}")
                if any(hint in name_lower for hint in SUSPICIOUS_NAME_HINTS):
                    reasons.append("nome suspeito")
                if reasons:
                    suspicious.append({"path": full_path, "reasons": reasons})
        return {
            "path": path,
            "scanned_files": scanned,
            "suspicious_found": len(suspicious),
            "suspicious": suspicious,
            "timestamp": datetime.now().isoformat(),
        }

    @staticmethod
    def hash_file(path: str) -> Dict[str, Any]:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return {
            "path": path,
            "size_bytes": os.path.getsize(path),
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest(),
        }

    @staticmethod
    def check_permissions(path: str) -> Dict[str, Any]:
        st = os.stat(path)
        mode = stat.filemode(st.st_mode)
        world_writable = bool(st.st_mode & stat.S_IWOTH)
        return {
            "path": path,
            "mode": mode,
            "octal": oct(st.st_mode)[-3:],
            "owner_uid": st.st_uid,
            "world_writable": world_writable,
            "warning": "Permissões world-writable — risco de segurança" if world_writable else None,
        }

    @staticmethod
    def generate_password(length: int = 16, symbols: bool = True) -> Dict[str, Any]:
        alphabet = string.ascii_letters + string.digits
        if symbols:
            alphabet += "!@#$%^&*()-_=+"
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        return {"password": password, "length": length}
