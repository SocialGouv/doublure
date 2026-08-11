"""HTTP client for the personal-data detector.

Same shape as the infrastructure client, and the same rule: an outage
propagates as `DetectionUnavailable`, never as an empty result. Returning no
spans on a failure would be indistinguishable from "there was no name in that
text" — and the whole reason this pass exists is that the two were already
indistinguishable.
"""
from __future__ import annotations

from typing import Any

import httpx

from ..detect import DetectionUnavailable
from .spans import couper_echafaudage, garder, merge_fragments, resserrer

#: Étiquettes du modèle vers nos types. Une entrée n'est ajoutée ici QUE
#: lorsque le moteur sait produire un substitut de même nature : une date tirée
#: au hasard détruit la chronologie qu'elle datait, et une adresse rendue en
#: mot n'est plus une adresse. La correspondance est ici, une seule fois — la
#: dupliquer dans le service ferait deux endroits où la changer.
TYPES_ACTIFS = {
    "person": "PERSON",
    "date": "DATE",
    "address": "ADDRESS",
}


class PiiClient:
    def __init__(self, base_url: str, *, timeout: float = 60.0,
                 min_score: float = 0.5):
        self.base_url = base_url.rstrip("/")
        self.min_score = min_score
        self._client = httpx.Client(timeout=timeout)

    def detect(self, text: str) -> list[dict[str, Any]]:
        if not text.strip():
            return []
        try:
            reponse = self._client.post(f"{self.base_url}/detect",
                                        json={"text": text})
            reponse.raise_for_status()
            brut = reponse.json()["entities"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise DetectionUnavailable(
                f"détecteur de données personnelles injoignable "
                f"({self.base_url}) : {exc}") from exc

        spans = [
            {**s, "type": TYPES_ACTIFS[s["type"]]}
            for s in brut
            if s.get("type") in TYPES_ACTIFS and s.get("score", 0) >= self.min_score
        ]
        # Recomposer AVANT de filtrer : la garde de forme juge une ENTITÉ, et
        # un fragment n'en est pas une — `Ferreira-K` seul n'a ni deux mots ni
        # majuscule là où l'entier en a. Puis couper l'échafaudage de la sortie
        # d'outil, qu'une entité à cheval sur deux lignes avale.
        entiers = resserrer(
            couper_echafaudage(merge_fragments(spans, text), text), text)
        return [s for s in entiers if garder(s)]

    def health(self) -> dict[str, Any]:
        try:
            reponse = self._client.get(f"{self.base_url}/healthz")
            reponse.raise_for_status()
            return reponse.json()
        except httpx.HTTPError as exc:
            raise DetectionUnavailable(f"{self.base_url} : {exc}") from exc

    def close(self) -> None:
        self._client.close()
