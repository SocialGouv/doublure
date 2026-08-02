"""Table de priorité des recouvrements (plan §5 Phase 2, tâche 4).

Quand deux détecteurs matchent la même sous-chaîne, l'ordre DOIT être
déterministe — sinon deux exécutions produisent des sorties différentes et le
cache de prompt saute (sans parler de l'incohérence de substitution).

Ordre appliqué :

1. **SECRET d'abord**, absolument. Un secret avalé par un span plus long
   deviendrait réversible via le coffre — violation de D4. Il gagne même
   quand il est plus court ou moins bien scoré.
2. **PUBLIC en dernier**, symétriquement. Un span PUBLIC n'est pas substitué :
   s'il gagne un arbitrage, la zone reste EN CLAIR. Comme il est souvent plus
   long (``SERVICE`` couvre ``db-master.acme.internal running`` là où
   ``HOSTNAME`` s'arrête à l'hôte), le critère de longueur le faisait gagner
   et le nom d'hôte réel sortait tel quel. Un span PUBLIC ne conserve donc que
   ce qu'aucune classe substituable ne revendique.
3. **Span le plus long** ensuite. Sur un recouvrement PARTIEL, prendre le
   span le plus court laisserait le reste en clair : ``alice.demo@ex.org``
   arbitré en faveur de ``ex.org`` (URL) laisserait fuir ``alice.demo``.
3. **Priorité de type** (table du plan §5 : ID technique > EMAIL > HOSTNAME >
   IP > NOM) pour départager les spans de MÊME étendue — c'est le cas que le
   plan décrit (« deux détecteurs matchent la même sous-chaîne »).
4. Score, puis type et position : uniquement pour rendre l'ordre total et
   donc le résultat déterministe.
"""
from __future__ import annotations

from typing import Any

from .classes import DataClass, class_of, priority_of


def _sort_key(span: dict[str, Any]) -> tuple:
    classe = class_of(span["type"])
    return (
        0 if classe is DataClass.SECRET else 1,
        1 if classe is DataClass.PUBLIC else 0,
        -(span["end"] - span["start"]),
        priority_of(span["type"]),
        -float(span.get("score", 0.0)),
        span["type"],
        span["start"],
    )


def resolve_overlaps(spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Retourne les spans retenus, sans recouvrement, triés par position.

    Un span perdant n'est pas jeté : sa partie NON RECOUVERTE est conservée
    comme fragment. Sinon, sur un recouvrement partiel, le reste du span
    perdant sortirait en clair — `…?login=alice@acme.com` arbitré en faveur
    d'un span URL plus long laissait fuir la fin du domaine réel.
    """
    kept: list[dict[str, Any]] = []
    for span in sorted(spans, key=_sort_key):
        for piece in _uncovered(span, kept):
            kept.append(piece)
    return sorted(kept, key=lambda s: s["start"])


def _uncovered(span: dict[str, Any], kept: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Morceaux de ``span`` qu'aucun span déjà retenu ne couvre."""
    pieces = [(span["start"], span["end"])]
    for k in kept:
        out: list[tuple[int, int]] = []
        for start, end in pieces:
            if k["end"] <= start or k["start"] >= end:
                out.append((start, end))
                continue
            if start < k["start"]:
                out.append((start, k["start"]))
            if k["end"] < end:
                out.append((k["end"], end))
        pieces = out
        if not pieces:
            break
    return [{**span, "start": s, "end": e} for s, e in pieces if e > s]
