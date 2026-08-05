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
        # Une entrée écrite TOUT EN MINUSCULES désigne un identifiant
        # insensible à la casse (nom d'hôte, chemin d'import, espace de noms) :
        # `GitHub.com/spf13/cobra` et `LOCALHOST` sont les mêmes valeurs
        # publiques, et les substituer privait le modèle de la référence sans
        # rien protéger. Une entrée qui porte une majuscule l'a VOULUE —
        # `Mail.Read` est une permission, pas un mot. La casse de l'entrée
        # déclare elle-même si la casse compte.
        self.insensibles = {e for e in exact if e == e.lower()}
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
        return self.is_exact(value) or any(p.fullmatch(value) for p in self.patterns)

    def is_exact(self, value: str) -> bool:
        """Prédicat pour une SOUS-PARTIE d'une valeur composite.

        Une entrée exacte est une décision prise token par token
        (« `python3.12-slim` est public ») : elle vaut partout. Une règle de
        FORME (`re:`) suppose au contraire un contexte — celle qui reconnaît un
        nom de fichier vaut pour de la prose (« ouvre `README.md` »), pas pour
        un segment d'URL ni un tag d'image, où rien ne désambiguïse et où elle
        laissait sortir `tenant-acme-nda.md` ou `client-nda-2025.zip` verbatim.
        """
        return value in self.exact or value.lower() in self.insensibles
