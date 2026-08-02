"""Lecture de l'allowlist §6 — « ce qui est public et ne se substitue jamais ».

Le fichier vit dans `config/`, terrain neutre : le service de détection (côté
GPL) et le moteur de substituts (côté nôtre) le lisent tous les deux. Le
PARSEUR est volontairement dupliqué de part et d'autre de la frontière D7 —
dix lignes de code contre une dépendance de licence, le choix est vite fait.
Ce qui compte est que la LISTE, elle, ne soit maintenue qu'une fois.

Sans cela, « ce token est standard » vivait à deux endroits : l'allowlist pour
les entités détectées, et une regex séparée dans le moteur pour les tags
d'image. Ajouter `python3.12-slim` demandait d'éditer les deux.
"""
from __future__ import annotations

import re
from pathlib import Path

DEFAULT_ALLOWLIST = Path(__file__).resolve().parents[2] / "config" / "allowlist.txt"


class Allowlist:
    """Prédicat « cette chaîne est publique »."""

    def __init__(self, exact: set[str], patterns: list[re.Pattern[str]]):
        self.exact = exact
        self.patterns = patterns

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Allowlist":
        p = Path(path) if path is not None else DEFAULT_ALLOWLIST
        if not p.exists():
            raise FileNotFoundError(f"allowlist introuvable : {p}")
        exact: set[str] = set()
        patterns: list[re.Pattern[str]] = []
        for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("re:"):
                try:
                    patterns.append(re.compile(line[3:]))
                except re.error as exc:
                    raise ValueError(f"{p}:{lineno} — regex invalide : {exc}") from exc
            else:
                exact.add(line)
        return cls(exact, patterns)

    def __call__(self, value: str) -> bool:
        return value in self.exact or any(p.fullmatch(value) for p in self.patterns)
