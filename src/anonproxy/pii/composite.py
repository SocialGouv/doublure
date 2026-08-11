"""Two detectors, one stream of spans.

The infrastructure detector and the personal-data one see different things and
neither subsumes the other: a cyber NER has no `PERSON`, a privacy model has no
`K8S_NAMESPACE`. Composing them is what closes the class rather than trading
one blind spot for another.

**An outage of either one is a refusal.** Continuing without the personal-data
pass would silently restore today's behaviour — names leaving in the clear with
nothing to count — and "no default opens anything, not even an outage" is the
line this project does not cross. Disabling the pass stays possible, as an
explicit setting: a decision the operator takes and that gets traced, never one
a failure takes for them.
"""
from __future__ import annotations

from typing import Any

from .spans import spans_inventaire


class CompositeDetector:
    def __init__(self, infrastructure, personnel, inventory=None):
        self.infrastructure = infrastructure
        self.personnel = personnel
        #: L'inventaire n'est pas un troisième détecteur : c'est une CERTITUDE
        #: de l'opérateur. Il produit ses propres spans là où aucun modèle n'a
        #: rien vu — sans quoi « ce nom est à nous » dépendrait qu'un modèle
        #: remarque le mot.
        self.inventory = inventory

    def detect(self, text: str, *, strategy: str | None = None) -> list[dict[str, Any]]:
        """`DetectionUnavailable` de l'une OU l'autre propage : fail-closed."""
        spans = list(self.infrastructure.detect(text, strategy=strategy))
        spans += list(self.personnel.detect(text))
        # Triés par position : le moteur arbitre les recouvrements, et il le
        # fait sur un flux ordonné. Deux sources concaténées ne le sont pas.
        if self.inventory is not None:
            spans += spans_inventaire(text, self.inventory, spans)
        spans.sort(key=lambda s: (s["start"], -(s["end"] - s["start"])))
        return spans

    def health(self) -> dict[str, Any]:
        return {"infrastructure": self.infrastructure.health(),
                "personnel": self.personnel.health()}

    def close(self) -> None:
        # Les deux, quoi qu'il arrive à la première : une fermeture qui s'arrête
        # au premier échec laisse une connexion ouverte pour toujours.
        try:
            self.infrastructure.close()
        finally:
            self.personnel.close()
