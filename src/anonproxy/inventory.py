"""Lecture de l'inventaire — « ce qui est À NOUS, et n'est donc jamais public ».

Inverse logique de l'allowlist, et son miroir : même terrain neutre (`config/`),
même parseur dupliqué de part et d'autre de la frontière D7, même principe —
c'est la LISTE qui est maintenue une fois, pas le code qui la lit.

L'allowlist répond « cette FORME est publique ». L'inventaire répond « ce NOM
est à nous », et il PRIME : `org.apache.kafka.acmecorp.PaymentsClient` et
`org.apache.kafka.clients.KafkaProducer` ont exactement la même forme, seul
l'inventaire les sépare. C'est ce que les rounds 8 à 14 ont écrit une dizaine
de fois sous le nom de « question d'INVENTAIRE, pas de forme ».

Sens de la garde : l'inventaire ne peut que REMONTER la protection. Il ne rend
jamais rien public, donc il ne peut pas introduire de fuite silencieuse — le
seul mode d'échec du système qui ne se voie pas.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

DEFAULT_INVENTORY = Path(__file__).resolve().parents[2] / "config" / "inventory.txt"

#: L'inventaire réel nomme l'organisation, ses zones et ses préfixes d'équipe :
#: c'est la liste qu'un dépôt public ne doit surtout pas recevoir par un `git
#: add` distrait. Cette variable le fait vivre hors de l'arbre de travail, comme
#: `ANON_ALLOWLIST_FILE` le permet déjà pour l'allowlist.
ENV_INVENTORY = "ANON_INVENTORY_FILE"

#: Séparateurs de segments d'un identifiant composite. Un nom nous appartient
#: dès qu'un de ses segments est à nous : `tenant-acmecorp-nda`,
#: `registry.k8s.io/acmecorp-billing` et `vnd.acmecorp.billing+json` doivent
#: tous être reconnus, et ils ne partagent aucune forme.
_SEGMENTS_RE = re.compile(r"[.:/@+_\-]+")


class Inventory:
    """Prédicat « cette chaîne nous appartient »."""

    def __init__(self, labels: set[str], patterns: list[re.Pattern[str]]):
        # Les labels sont comparés en minuscules : un nom d'hôte ou de paquet
        # est insensible à la casse, et `AcmeCorp` est la même organisation
        # qu'`acmecorp`. C'est l'inverse de l'allowlist, où la casse d'une
        # entrée DÉCLARE si elle compte — ici il n'y a qu'un sens possible,
        # puisque manquer une variante de casse serait manquer une fuite.
        self.labels = {l.lower() for l in labels}
        self.patterns = patterns

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Inventory":
        demande = path if path is not None else os.environ.get(ENV_INVENTORY)
        p = Path(demande) if demande is not None else DEFAULT_INVENTORY
        if not p.exists():
            if demande is not None:
                # Un chemin DEMANDÉ qui n'existe pas est une faute de frappe,
                # pas un dépôt sans inventaire : le lire comme vide rendrait
                # publics les noms qu'il devait fermer, en silence.
                raise FileNotFoundError(f"inventaire introuvable : {p}")
            # Un inventaire absent à l'emplacement par défaut n'est pas une
            # erreur : c'est l'état d'un dépôt qui n'en a pas encore constitué
            # un. Il n'ouvre rien — l'allowlist décide alors seule, comme avant.
            return cls(set(), [])
        labels: set[str] = set()
        patterns: list[re.Pattern[str]] = []
        for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("re:"):
                try:
                    patterns.append(re.compile(line[3:], re.I))
                except re.error as exc:
                    raise ValueError(f"{p}:{lineno} — regex invalide : {exc}") from exc
            else:
                labels.add(line)
        return cls(labels, patterns)

    def est_a_nous(self, value: str) -> bool:
        if any(p.fullmatch(value) for p in self.patterns):
            return True
        return any(seg.lower() in self.labels
                   for seg in _SEGMENTS_RE.split(value) if seg)

    def __bool__(self) -> bool:
        return bool(self.labels or self.patterns)
