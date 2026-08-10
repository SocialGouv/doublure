"""Lecture de l'allowlist §6 — « ce qui est public et ne se substitue jamais ».

Le fichier vit dans `config/`, terrain neutre : le service de détection (côté
GPL) et le moteur de substituts (côté nôtre) le lisent tous les deux. Le
PARSEUR est volontairement dupliqué de part et d'autre de la frontière D7 —
dix lignes de code contre une dépendance de licence, le choix est vite fait.
Ce qui compte est que la LISTE, elle, ne soit maintenue qu'une fois.

Sans cela, « ce token est standard » vivait à deux endroits : l'allowlist pour
les entités détectées, et une regex séparée dans le moteur pour les tags
d'image. Ajouter `python3.12-slim` demandait d'éditer les deux.

Trois formes de ligne :

    localhost                          exacte, publique pour TOUS les types
    re:k8s\\.io(/[\\w-]+)*               de forme, publique pour tous les types
    types:FILE_PATH,ORGANIZATION code  publique SEULEMENT sous ces types

La portée par TYPE existe parce que l'allowlist était type-agnostique : elle
répondait « cette valeur est publique », jamais « publique QUAND elle est un
chemin de fichier ». Déclarer `code` public tout court faisait sortir verbatim
une machine réellement nommée `code`. Sans type connu, une entrée typée ne
s'applique PAS : qui ne sait pas de quoi il parle n'ouvre rien.
"""
from __future__ import annotations

import re
from pathlib import Path

DEFAULT_ALLOWLIST = Path(__file__).resolve().parents[2] / "config" / "allowlist.txt"

#: Préfixe déclarant les types d'entité auxquels une entrée se limite.
PREFIXE_TYPES = "types:"


class Allowlist:
    """Prédicat « cette chaîne est publique »."""

    def __init__(self, exact: set[str], patterns: list[re.Pattern[str]],
                 types: dict[str, frozenset[str]] | None = None,
                 patterns_types: list[tuple[re.Pattern[str], frozenset[str]]]
                 | None = None):
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
        #: Entrée exacte -> types auxquels elle se limite.
        self.types = types or {}
        #: Règles de forme typées, gardées à part : leur portée se lit sur la
        #: règle, pas sur la valeur.
        self.patterns_types = patterns_types or []

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Allowlist":
        p = Path(path) if path is not None else DEFAULT_ALLOWLIST
        if not p.exists():
            raise FileNotFoundError(f"allowlist introuvable : {p}")
        exact: set[str] = set()
        patterns: list[re.Pattern[str]] = []
        types: dict[str, frozenset[str]] = {}
        patterns_types: list[tuple[re.Pattern[str], frozenset[str]]] = []
        for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            portee: frozenset[str] | None = None
            if line.startswith(PREFIXE_TYPES):
                tete, _, reste = line.partition(" ")
                portee = frozenset(
                    t for t in tete[len(PREFIXE_TYPES):].split(",") if t)
                line = reste.strip()
                if not portee or not line:
                    raise ValueError(
                        f"{p}:{lineno} — entrée typée incomplète : il faut "
                        f"`types:TYPE1,TYPE2 <entrée>`")

            if line.startswith("re:"):
                try:
                    motif = re.compile(line[3:])
                except re.error as exc:
                    raise ValueError(f"{p}:{lineno} — regex invalide : {exc}") from exc
                if portee is None:
                    patterns.append(motif)
                else:
                    patterns_types.append((motif, portee))
            elif portee is None:
                exact.add(line)
            else:
                types[line] = portee
        return cls(exact, patterns, types, patterns_types)

    def __call__(self, value: str, etype: str | None = None) -> bool:
        if self.is_exact(value, etype):
            return True
        if any(p.fullmatch(value) for p in self.patterns):
            return True
        return etype is not None and any(
            etype in portee and motif.fullmatch(value)
            for motif, portee in self.patterns_types)

    def is_exact(self, value: str, etype: str | None = None) -> bool:
        """Prédicat pour une SOUS-PARTIE d'une valeur composite.

        Une entrée exacte est une décision prise token par token
        (« `python3.12-slim` est public ») : elle vaut partout. Une règle de
        FORME (`re:`) suppose au contraire un contexte — celle qui reconnaît un
        nom de fichier vaut pour de la prose (« ouvre `README.md` »), pas pour
        un segment d'URL ni un tag d'image, où rien ne désambiguïse et où elle
        laissait sortir `tenant-acme-nda.md` ou `client-nda-2025.zip` verbatim.

        Une entrée TYPÉE, elle, ne vaut que sous ses types — et pas du tout
        quand le type est inconnu : c'est le sens fermé, celui qui n'ouvre rien
        par défaut.
        """
        if value in self.exact or value.lower() in self.insensibles:
            return True
        if etype is None:
            return False
        portee = self.types.get(value) or self.types.get(value.lower())
        return portee is not None and etype in portee
