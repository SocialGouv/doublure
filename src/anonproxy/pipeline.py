"""Pipeline de pseudonymisation : texte réel → texte à substituts.

C'est l'implémentation de ``Substituter.to_surrogate`` attendue par le walker.

Chaîne : détection (AnonShield, HTTP) → arbitrage des recouvrements →
substituts plausibles (moteur Phase 2) → texte réécrit.

Déterminisme : un cache mémoire par portée garantit qu'une même chaîne produit
exactement le même résultat dans la session (et le moteur le garantit entre
sessions). C'est ce qui préserve le préfixe de cache de prompt d'Anthropic —
Claude Code renvoie system + tools identiques à chaque tour.
"""
from __future__ import annotations

import logging
import re
import threading
from collections import OrderedDict

from .detect import DetectClient
from .surrogates.engine import SurrogateEngine

logger = logging.getLogger("anonproxy.pipeline")

#: Seul un texte SANS aucun caractère alphanumérique ne peut porter
#: d'identifiant. Tout le reste passe au détecteur.
#:
#: Un seuil de longueur serait une fuite : le pipeline est appelé sur chaque
#: FEUILLE JSON isolée, et un `metadata.user_id` de 4 caractères, un nom
#: d'hôte court sans domaine ou une valeur d'enum interne (`db01`, `jdoe`)
#: partiraient alors en clair sans jamais être analysés.
_HAS_ALNUM = re.compile(r"\w", re.UNICODE)


class Pseudonymizer:
    """Callable injecté dans ``Substituter.to_surrogate``."""

    def __init__(self, detector: DetectClient, engine: SurrogateEngine, *, cache_size: int = 20000):
        self.detector = detector
        self.engine = engine
        self.cache_size = cache_size
        self._cache: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._lock = threading.RLock()
        self.stats = {"calls": 0, "cache_hits": 0, "detected": 0, "substituted": 0}

    def __call__(self, text: str) -> str:
        return self.to_surrogate(text)

    def to_surrogate(self, text: str) -> str:
        if not text or not _HAS_ALNUM.search(text):
            return text

        # La portée fait partie de la clé : un même texte donne des substituts
        # différents d'un projet à l'autre (réponse §3.1). Sans elle, réutiliser
        # un Pseudonymizer entre deux portées contaminerait la seconde.
        key = (self.engine.scope_key, text)
        with self._lock:
            self.stats["calls"] += 1
            hit = self._cache.get(key)
            if hit is not None:
                self._cache.move_to_end(key)
                self.stats["cache_hits"] += 1
                return hit

        spans = self.detector.detect(text)  # DetectionUnavailable propage (fail-closed)
        if not spans:
            out = text
        else:
            out = self.engine.transform(text, spans)

        with self._lock:
            self.stats["detected"] += len(spans)
            if out != text:
                self.stats["substituted"] += 1
            self._cache[key] = out
            self._cache.move_to_end(key)
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)
        return out

    def surrogates_view(self) -> dict[str, str]:
        return self.engine.surrogates_view()
