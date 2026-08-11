"""Reassembling a name the model returned in pieces.

Measured on the real model: `Ines Ferreira-Konate` comes back as
`' Ines Ferreira-K'` then `'onate'`, two spans of the same label. Substituting
them separately puts half a name in the vault and lets the other half leave —
a leak that looks like a substitution, which is the worst shape a defect can
take here.

Merging by OFFSET rather than by text, because the text is exactly what is
fragmented. And the negative cases carry as much weight: two people separated
by a comma are two people, and welding them together would produce one
surrogate for two humans — the injectivity breach (D6) seen from the other end.
"""
from __future__ import annotations

import pytest

from anonproxy.pii.spans import merge_fragments

TEXTE = ("Ouvert par Ines Ferreira-Konate. Reprise par Thibault Escourrou, "
         "astreinte. Commande de Marguerite Vasseur.")


def _span(valeur: str, label: str = "PERSON", texte: str = TEXTE) -> dict:
    debut = texte.index(valeur)
    return {"type": label, "value": valeur,
            "start": debut, "end": debut + len(valeur), "score": 1.0}


def test_subword_pieces_become_one_entity():
    """Le cas mesuré : le modèle coupe au milieu du mot."""
    fragments = [_span("Ines Ferreira-K"), _span("onate")]
    fusion = merge_fragments(fragments, TEXTE)
    assert [s["value"] for s in fusion] == ["Ines Ferreira-Konate"]


def test_a_space_inside_a_name_is_crossed():
    """Prénom et nom arrivent en deux spans : les garder séparés substituerait
    le prénom seul, et le nom partirait."""
    fusion = merge_fragments([_span("Marguerite"), _span("Vasseur")], TEXTE)
    assert [s["value"] for s in fusion] == ["Marguerite Vasseur"]


def test_two_people_separated_by_punctuation_stay_two():
    """Les souder donnerait UN substitut pour DEUX personnes : c'est
    l'injectivité (D6) prise par l'autre bout."""
    fusion = merge_fragments(
        [_span("Thibault Escourrou"), _span("Marguerite Vasseur")], TEXTE)
    assert len(fusion) == 2


def test_two_people_separated_by_a_word_stay_two():
    texte = "opened by John Smith and handed to Mary Johnson"
    fusion = merge_fragments(
        [_span("John Smith", texte=texte), _span("Mary Johnson", texte=texte)],
        texte)
    assert [s["value"] for s in fusion] == ["John Smith", "Mary Johnson"]


def test_different_labels_never_merge():
    """Adjacents et de types différents : les fusionner inventerait une entité
    qu'aucun modèle n'a vue."""
    texte = "Paris Hilton"
    spans = [_span("Paris", "LOCATION", texte), _span("Hilton", "PERSON", texte)]
    fusion = merge_fragments(spans, texte)
    assert len(fusion) == 2


def test_the_merged_span_keeps_the_lowest_score():
    """Un fragment douteux ne doit pas être blanchi par un voisin certain : le
    seuil doit s'appliquer à ce que l'on garde vraiment."""
    a, b = _span("Ines Ferreira-K"), _span("onate")
    a["score"], b["score"] = 1.0, 0.62
    assert merge_fragments([a, b], TEXTE)[0]["score"] == pytest.approx(0.62)


def test_offsets_are_recomputed_not_guessed():
    fusion = merge_fragments([_span("Ines Ferreira-K"), _span("onate")], TEXTE)
    span = fusion[0]
    assert TEXTE[span["start"]:span["end"]] == span["value"]


def test_input_order_does_not_decide():
    """Le modèle ne garantit pas l'ordre ; trier fait partie de la fusion."""
    fusion = merge_fragments([_span("onate"), _span("Ines Ferreira-K")], TEXTE)
    assert [s["value"] for s in fusion] == ["Ines Ferreira-Konate"]


def test_a_leading_space_is_not_part_of_the_name():
    """Le modèle rend ` Ines`, espace compris. Le garder ferait entrer au
    coffre une valeur qui ne correspond à aucun jeton du texte."""
    texte = "par Ines Ferreira"
    span = {"type": "PERSON", "value": " Ines Ferreira", "start": 3,
            "end": 17, "score": 1.0}
    fusion = merge_fragments([span], texte)
    assert fusion[0]["value"] == "Ines Ferreira"
    assert texte[fusion[0]["start"]:fusion[0]["end"]] == "Ines Ferreira"


def test_no_spans_is_not_an_error():
    assert merge_fragments([], TEXTE) == []
