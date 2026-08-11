"""The inventory must be able to CREATE a span, not only to close one.

Measured while proving that a shell command's output is protected:

    kubectl get pods -n acmecorp-billing -o wide
        detector → [TOOL: kubectl]

`acmecorp-billing` is not detected as anything. It is a Kubernetes namespace,
it carries the organisation's name, and `acmecorp` is declared in the operator's
inventory — and it left in the clear anyway, because the inventory could only
SUBTRACT from what the detector had already found.

That makes the operator's one unambiguous instruction — "this name is ours" —
conditional on a model happening to notice the word. The documentation promised
the opposite: *an identifier is yours as soon as one of its segments matches*.

So the inventory becomes a source of spans in its own right. It can only ever
add protection, so it cannot introduce a silent leak; that is exactly why it is
the right place to put a certainty.
"""
from __future__ import annotations

import pytest

from anonproxy.inventory import Inventory
from anonproxy.pii.spans import spans_inventaire


@pytest.fixture
def inventaire(tmp_path):
    fichier = tmp_path / "inventory.txt"
    fichier.write_text("acmecorp\nacme\nre:[\\w-]+\\.acmecorp\\.internal\n",
                       encoding="utf-8")
    return Inventory.load(fichier)


def _valeurs(spans):
    return sorted(s["value"] for s in spans)


def test_a_declared_label_is_found_where_no_detector_saw_it(inventaire):
    texte = "kubectl get pods -n acmecorp-billing -o wide"
    spans = spans_inventaire(texte, inventaire, [])
    assert _valeurs(spans) == ["acmecorp-billing"]
    assert spans[0]["type"] == "INVENTORY"


def test_the_offsets_point_at_the_text(inventaire):
    texte = "namespace acmecorp-billing en production"
    for s in spans_inventaire(texte, inventaire, []):
        assert texte[s["start"]:s["end"]] == s["value"]


def test_what_a_detector_already_covers_is_not_doubled(inventaire):
    """Deux spans sur le même texte se disputeraient l'arbitrage des
    recouvrements, et le plus long gagnerait — pas forcément le plus juste."""
    texte = "hôte db-01.acmecorp.internal en panne"
    deja = [{"type": "HOSTNAME", "value": "db-01.acmecorp.internal",
             "start": texte.index("db-01"), "end": texte.index(" en"),
             "score": 0.99}]
    assert spans_inventaire(texte, inventaire, deja) == []


def test_a_word_that_is_not_ours_is_not_invented(inventaire):
    texte = "kubectl get pods -n kube-system -o wide"
    assert spans_inventaire(texte, inventaire, []) == []


def test_a_bare_label_counts_too(inventaire):
    texte = "le compte acmecorp est suspendu"
    assert _valeurs(spans_inventaire(texte, inventaire, [])) == ["acmecorp"]


def test_a_label_inside_a_longer_word_is_not_a_match(inventaire):
    """`acmecorporation` n'est pas `acmecorp` : un segment se délimite, sinon
    l'inventaire substituerait du vocabulaire qui lui ressemble."""
    texte = "la société acmecorporation nous a écrit"
    assert spans_inventaire(texte, inventaire, []) == []


def test_every_occurrence_is_found(inventaire):
    texte = "acmecorp-billing appelle acmecorp-payments"
    assert _valeurs(spans_inventaire(texte, inventaire, [])) == [
        "acmecorp-billing", "acmecorp-payments"]


def test_an_empty_inventory_produces_nothing():
    """Construit vide, pas chargé depuis un chemin absent : un inventaire
    DEMANDÉ et introuvable lève, et c'est voulu — le lire comme vide rouvrirait
    en silence les noms qu'il devait fermer."""
    assert spans_inventaire("acmecorp-billing", Inventory(set(), []), []) == []
