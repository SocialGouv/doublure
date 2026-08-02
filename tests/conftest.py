"""Détecteurs factices partagés par les tests.

Cinq classes quasi identiques circulaient dans les fichiers de tests, dont
deux copies littérales du même espion dans un seul fichier.

Les fabriques de moteur, elles, restent locales à chaque fichier : chacune
utilise une clé maître distincte, et le déterminisme des substituts en dépend.
"""
from __future__ import annotations

from anonproxy.detect import DetectionUnavailable


class RecordingDetector:
    """Mémorise les textes reçus, ne détecte rien.

    Sert à vérifier CE QUI est soumis au détecteur — notamment qu'aucun seuil
    de longueur n'écarte silencieusement une valeur courte.
    """

    def __init__(self):
        self.seen: list[str] = []

    def detect(self, text, *, strategy=None):
        self.seen.append(text)
        return []

    def health(self):
        return {"status": "ok", "warm": True}

    def close(self):
        pass


class DeadDetector:
    """Détecteur en panne : vérifie que le refus est bien fail-closed."""

    def detect(self, text, *, strategy=None):
        raise DetectionUnavailable("service arrêté")

    def health(self):
        raise DetectionUnavailable("service arrêté")

    def close(self):
        pass
