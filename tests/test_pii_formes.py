"""A span must look like what the model claims it is.

Measured on the real incident file: the ticket number `4218` came back as an
`ADDRESS` at 1.00 and was substituted, so the document the model read was about
incident `1000`. And `lica-` — four letters taken from the middle of
`db-replica-02-prod` — came back as an `ADDRESS` too.

Neither is a leak: they substitute MORE than needed, which is the harmless
direction. But both damage the text, and a model that reads a mangled document
answers about a mangled document.

The guard is on SHAPE, and it is deliberately crude: a number with no letter is
not an address, a lone lowercase word is not a person. Anything richer would be
a second detector arguing with the first.
"""
from __future__ import annotations

import pytest

from anonproxy.pii.spans import garder


def _span(valeur, etype="PERSON"):
    return {"type": etype, "value": valeur, "start": 0,
            "end": len(valeur), "score": 1.0}


@pytest.mark.parametrize("valeur", [
    "4218",            # le NUMÉRO du ticket, rendu ADDRESS à 1.00
    "75006",           # un code postal seul n'est pas une adresse
    "lica-",           # un fragment pris au milieu d'un nom d'hôte
])
def test_these_are_not_addresses(valeur):
    assert not garder(_span(valeur, "ADDRESS")), valeur


@pytest.mark.parametrize("valeur", [
    "14 rue des Grands-Augustins",
    "75006 Paris",
    "221B Baker Street, London",
])
def test_these_are(valeur):
    assert garder(_span(valeur, "ADDRESS")), valeur


@pytest.mark.parametrize("valeur", [
    "14",              # un nombre n'est pas quelqu'un
    "impact",          # un mot commun en minuscule
    "-",
])
def test_these_are_not_people(valeur):
    assert not garder(_span(valeur, "PERSON")), valeur


@pytest.mark.parametrize("valeur", [
    "Ines Ferreira-Konate",
    "Thibault Escourrou (astreinte",   # le span déborde, la personne est là
    "Marguerite Vasseur",
    "Vasseur",                          # un patronyme seul, capitalisé
])
def test_these_are_people(valeur):
    assert garder(_span(valeur, "PERSON")), valeur


def test_a_date_needs_a_digit():
    assert not garder(_span("printemps", "DATE"))
    assert garder(_span("12 mars 2019", "DATE"))


def test_an_unknown_type_is_kept():
    """La garde écarte ce qu'elle sait faux, elle ne décide pas à la place des
    types qu'elle ne connaît pas."""
    assert garder(_span("n'importe quoi", "HOSTNAME"))
