"""A date span rarely holds only a date, and a word is not a date.

Measured in a real session: the detector returned `3 février 2026 à 14h32` —
the field as it is written in the ticket — and the parser, which demanded a
bare date, matched nothing. The value then fell through to the generic
substitution and came back as `registry-vale3`.

Nothing leaked. But the model read a hostname where the document announced an
opening date, said it could not read it as a date, and **refused to answer the
"when" part of the question**. That is the surrogate invariant broken:
indistinguishable IN NATURE is not a nicety, it is what keeps the agent able to
work.

The test that was supposed to cover this asserted only that the output differed
from the input — which a word satisfies. It checked "protected", not "of the
same nature", while the invariant it needed was already written down two
modules away.
"""
from __future__ import annotations

import datetime as dt
import re

import pytest

from anonproxy.allowlist import DEFAULT_ALLOWLIST
from anonproxy.proxy.app import predicat_public
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "c3" * 32


@pytest.fixture
def m(tmp_path):
    return SurrogateEngine(
        vault=Vault(tmp_path / "v.db", master_key=MASTER), master_key=MASTER,
        scope_key="project:dates-entourees",
        is_public=predicat_public(DEFAULT_ALLOWLIST))


def sub(m, valeur):
    return m.substitute_value("DATE", valeur)


@pytest.mark.parametrize("reel, garde", [
    ("3 février 2026 à 14h32", "à 14h32"),      # le champ, tel qu'il est écrit
    ("le 3 février 2026", "le "),               # une préposition devant
    ("ouvert le 3 février 2026,", "ouvert le "),
    ("2026-02-03 14:32:11", "14:32:11"),
    ("du 12 mars 2019 au", "du "),
])
def test_the_surround_survives_and_the_date_moves(m, reel, garde):
    sortie = sub(m, reel)
    assert garde in sortie, f"{reel!r} -> {sortie!r} : l'entourage a disparu"
    assert sortie != reel


@pytest.mark.parametrize("reel", [
    "3 février 2026 à 14h32",
    "le 3 février 2026",
    "2026-02-03 14:32:11",
])
def test_a_date_still_comes_back_a_date(m, reel):
    """L'invariant : indiscernable EN NATURE. Un mot d'hôte à la place d'une
    date rend le document illisible là où il annonce une chronologie."""
    sortie = sub(m, reel)
    assert re.search(r"\d{1,2} [a-zéûî]+ \d{4}|\d{4}-\d{2}-\d{2}", sortie), \
        f"{reel!r} -> {sortie!r} : ce n'est plus une date"


def test_the_interval_survives_the_surround(m):
    """Le décalage doit rester le MÊME, que la date soit nue ou entourée —
    sinon deux lignes du même incident se contredisent."""
    nue = sub(m, "2026-02-03")
    entouree = sub(m, "le 2026-02-24 à 09:00")
    a = dt.date.fromisoformat(nue)
    b = dt.date.fromisoformat(re.search(r"\d{4}-\d{2}-\d{2}", entouree).group())
    assert (b - a).days == 21


def test_a_span_with_no_date_at_all_is_still_substituted(m):
    """Résidu assumé : sans date lisible, la nature ne peut pas être tenue.
    La valeur reste protégée — c'est le sens sûr — et le cas est nommé."""
    assert sub(m, "la semaine dernière") != "la semaine dernière"
