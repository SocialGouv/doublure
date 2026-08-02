"""Client HTTP du service AnonShield (frontière D7 : processus séparé).

Aucun import depuis ``services/anonshield`` — uniquement du HTTP. Toute panne
du détecteur remonte en erreur explicite : sans détection, on ne laisse RIEN
partir (fail-closed).
"""
from __future__ import annotations

from typing import Any

import httpx


class DetectionUnavailable(RuntimeError):
    """Le détecteur est injoignable ou en erreur : on refuse d'émettre."""


class DetectClient:
    def __init__(self, base_url: str, *, timeout: float = 30.0, regex_threshold: int = 8000):
        self.base_url = base_url.rstrip("/")
        self.regex_threshold = regex_threshold
        self._client = httpx.Client(timeout=timeout)

    def detect(self, text: str, *, strategy: str | None = None) -> list[dict[str, Any]]:
        """Détecte les entités. Les textes volumineux sont DÉCOUPÉS, jamais
        rétrogradés en `regex`.

        Basculer en `regex` au-delà d'un seuil désactivait le NER — donc
        ORGANIZATION, LOCATION et PERSON — précisément sur les gros volumes de
        logs, qui sont le cas d'usage. Le découpage borne la latence sans
        sacrifier la couverture.
        """
        if strategy is None and len(text) > self.regex_threshold:
            return self._detect_chunked(text)
        if strategy is None:
            strategy = "filtered"
        try:
            r = self._client.post(
                f"{self.base_url}/detect", json={"text": text, "strategy": strategy}
            )
            r.raise_for_status()
            return r.json()["entities"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise DetectionUnavailable(
                f"détection indisponible ({self.base_url}, stratégie={strategy}) : {exc}"
            ) from exc

    def _detect_chunked(self, text: str) -> list[dict[str, Any]]:
        """Découpe aux frontières de ligne et recolle les offsets.

        Un chevauchement conserve les entités à cheval sur une coupe ; les
        doublons introduits par ce chevauchement sont dédupliqués sur
        (start, end, type).
        """
        overlap = 256
        size = max(self.regex_threshold, overlap * 4)
        out: list[dict[str, Any]] = []
        seen: set[tuple[int, int, str]] = set()
        pos = 0
        while pos < len(text):
            end = min(pos + size, len(text))
            if end < len(text):  # couper sur une fin de ligne quand c'est possible
                nl = text.rfind("\n", pos + size - overlap, end)
                if nl > pos:
                    end = nl + 1
            for ent in self.detect(text[pos:end], strategy="filtered"):
                key = (ent["start"] + pos, ent["end"] + pos, ent["type"])
                if key in seen:
                    continue
                seen.add(key)
                out.append({**ent, "start": key[0], "end": key[1]})
            if end >= len(text):
                break
            pos = max(end - overlap, pos + 1)
        out.sort(key=lambda e: e["start"])
        return out

    def health(self) -> dict[str, Any]:
        try:
            r = self._client.get(f"{self.base_url}/healthz", timeout=5.0)
            r.raise_for_status()
            return r.json()
        except httpx.HTTPError as exc:
            raise DetectionUnavailable(f"détecteur injoignable ({self.base_url}) : {exc}") from exc

    def close(self) -> None:
        self._client.close()
