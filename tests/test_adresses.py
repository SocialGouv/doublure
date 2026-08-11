"""A postal address must come back an address, and designate nobody.

Two clauses of the same invariant, and the second is the one that bites: a
fictional street in a real city is nobody's address, but keeping the postcode
keeps the *locality* — and locality is what a re-identification attack joins
on. So the digits go too.

What stays is the vocabulary that identifies no one: `rue`, `avenue`, `street`.
Substituting those would produce something that is no longer an address, which
is the first clause broken to satisfy the second.
"""
from __future__ import annotations

import re

import pytest

from anonproxy.allowlist import DEFAULT_ALLOWLIST
from anonproxy.proxy.app import predicat_public
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "b9" * 32
REELLE = "14 rue des Grands-Augustins, 75006 Paris"


@pytest.fixture
def m(tmp_path):
    return SurrogateEngine(
        vault=Vault(tmp_path / "v.db", master_key=MASTER), master_key=MASTER,
        scope_key="project:adresses",
        is_public=predicat_public(DEFAULT_ALLOWLIST))


def sub(m, valeur=REELLE):
    return m.substitute_value("ADDRESS", valeur)


def test_it_still_looks_like_an_address(m):
    """Un substitut doit être indiscernable EN NATURE : numéro, voie, code,
    ville. Rendre un mot laisserait le modèle sans rien à comprendre."""
    assert re.match(r"^\d+ (rue|avenue|boulevard|impasse|place|chemin) "
                    r"[\w'’ -]+, \d{5} [\w'’-]+$", sub(m)), sub(m)


def test_nothing_of_the_real_address_survives(m):
    sortie = sub(m)
    for morceau in ("Grands", "Augustins", "75006", "Paris", "14 "):
        assert morceau not in sortie, f"{morceau!r} a survécu dans {sortie!r}"


def test_the_postcode_is_replaced_not_kept(m):
    """Garder le code postal garde la LOCALITÉ, et c'est exactement ce sur quoi
    une ré-identification recoupe."""
    code = re.search(r"(\d{5})", sub(m)).group(1)
    assert code != "75006"
    # Ni le département, qui est les deux premiers chiffres.
    assert not code.startswith("75")


def test_the_street_vocabulary_is_kept(m):
    """`rue` n'identifie personne, et le remplacer produirait une chaîne qui
    n'est plus une adresse."""
    assert " rue " in sub(m)


def test_an_english_form_keeps_its_own_vocabulary(m):
    sortie = m.substitute_value("ADDRESS", "221B Baker Street, London")
    assert " street" in sortie.lower(), sortie
    assert "Baker" not in sortie and "London" not in sortie


def test_it_is_deterministic(m):
    assert sub(m) == sub(m)


def test_two_addresses_do_not_collapse(m):
    autre = "9 avenue du Général-Leclerc, 33000 Bordeaux"
    assert sub(m) != m.substitute_value("ADDRESS", autre)


def test_a_partial_address_is_still_substituted(m):
    """Une adresse sans code postal reste une adresse : la rendre telle quelle
    serait une fuite silencieuse."""
    sortie = m.substitute_value("ADDRESS", "rue des Grands-Augustins")
    assert "Grands" not in sortie and "Augustins" not in sortie
    assert "rue" in sortie
