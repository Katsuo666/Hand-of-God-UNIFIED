# -*- coding: utf-8 -*-
"""Armazenamento de snapshots por alvo para o modo watch (monitorização contínua)."""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.config import Config

WATCH_DIR = Config.DATA_DIR / "watch"


def _safe_filename(target: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_\-.]', '_', target)[:100]


class WatchStore:
    """Guarda e recupera o último snapshot conhecido de um alvo, em JSON."""

    def __init__(self, base_dir: Path = WATCH_DIR):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True, parents=True)

    def _path(self, target: str) -> Path:
        return self.base_dir / f"{_safe_filename(target)}.json"

    def load(self, target: str) -> Optional[Dict[str, Any]]:
        path = self._path(target)
        if not path.exists():
            return None
        with open(path, encoding='utf-8') as f:
            return json.load(f)

    def save(self, target: str, data: Dict[str, Any]) -> Path:
        path = self._path(target)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return path


def diff_dicts(old: Any, new: Any, path: str = "") -> List[Tuple[str, Any, Any]]:
    """
    Diff recursivo simples entre dois valores (dict/list/escalar já desserializados de JSON).
    Retorna lista de (caminho, valor_antigo, valor_novo) para cada mudança encontrada.
    """
    changes: List[Tuple[str, Any, Any]] = []

    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old.keys()) | set(new.keys())):
            sub_path = f"{path}.{key}" if path else str(key)
            if key not in old:
                changes.append((sub_path, None, new[key]))
            elif key not in new:
                changes.append((sub_path, old[key], None))
            else:
                changes.extend(diff_dicts(old[key], new[key], sub_path))
    elif isinstance(old, list) and isinstance(new, list):
        if old != new:
            changes.append((path or "root", old, new))
    else:
        if old != new:
            changes.append((path or "root", old, new))

    return changes
