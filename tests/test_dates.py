"""A date is not substituted, it is SHIFTED — and that is the whole design.

An incident reads as a sequence. Drawing each date independently would turn
`14h32 → 14h58 → 15h20` and `opened 12 March, closed 3 April` into noise, and
the operator would be handed a chronology that contradicts itself — which is
exactly the failure the surrogate invariant was written for after three
defects of the same family.

One shift, constant per scope, keeps every interval intact while no date stays
itself. It is also injective by construction: a translation never maps two
distinct dates onto one.

The price is stated rather than discovered: **the interval between two dates is
preserved**, and joins the four attributes already accepted as leaks.
"""
from __future__ import annotations

import datetime as dt
import re

import pytest

from anonproxy.allowlist import DEFAULT_ALLOWLIST
from anonproxy.proxy.app import predicat_public
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "e2" * 32


def moteur(tmp_path, scope="project:dates"):
    return SurrogateEngine(
        vault=Vault(tmp_path / f"{scope.replace(':', '-')}.db", master_key=MASTER),
        master_key=MASTER, scope_key=scope,
        is_public=predicat_public(DEFAULT_ALLOWLIST))


@pytest.fixture
def m(tmp_path):
    return moteur(tmp_path)


def sub(m, valeur):
    return m.substitute_value("DATE", valeur)


# --------------------------------------------------------------------------- #
# La forme : un substitut doit être indiscernable EN NATURE
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("reel, motif", [
    ("2026-02-03", r"^\d{4}-\d{2}-\d{2}$"),
    ("03/02/2026", r"^\d{2}/\d{2}/\d{4}$"),
    ("03-02-2026", r"^\d{2}-\d{2}-\d{4}$"),
    ("12 mars 2019", r"^\d{1,2} [a-zéû]+ \d{4}$"),
    ("12 March 2019", r"^\d{1,2} [A-Za-z]+ \d{4}$"),
])
def test_the_format_survives(m, reel, motif):
    """Rendre une ISO là où il y avait « 12 mars 2019 » se remarque, et change
    la structure du texte que le modèle lit."""
    sortie = sub(m, reel)
    assert re.match(motif, sortie), f"{reel!r} -> {sortie!r}"
    assert sortie != reel


def test_a_timestamp_keeps_its_time(m):
    """Décaler l'heure casserait l'ordre des événements d'un incident, qui est
    précisément ce que l'agent doit pouvoir lire."""
    sortie = sub(m, "2026-02-03T14:32:00Z")
    assert sortie.endswith("T14:32:00Z"), sortie
    assert not sortie.startswith("2026-02-03")


# --------------------------------------------------------------------------- #
# La propriété : les intervalles tiennent
# --------------------------------------------------------------------------- #


def test_the_interval_between_two_dates_is_preserved(m):
    a, b = sub(m, "2026-02-03"), sub(m, "2026-02-24")
    ecart = dt.date.fromisoformat(b) - dt.date.fromisoformat(a)
    assert ecart.days == 21, f"{a} → {b}"


def test_the_order_of_events_is_preserved(m):
    dates = ["2026-01-05", "2026-02-03", "2026-11-30"]
    rendus = [dt.date.fromisoformat(sub(m, d)) for d in dates]
    assert rendus == sorted(rendus)


def test_the_shift_crosses_formats(m):
    """Le même jour écrit de deux façons doit tomber sur le même jour décalé,
    sinon un document se contredit selon la ligne qu'on lit."""
    iso = dt.date.fromisoformat(sub(m, "2026-02-03"))
    fr = sub(m, "03/02/2026")
    jour, mois, annee = (int(x) for x in fr.split("/"))
    assert dt.date(annee, mois, jour) == iso


# --------------------------------------------------------------------------- #
# Ce qui doit tenir de toute façon
# --------------------------------------------------------------------------- #


def test_the_result_is_a_real_date(m):
    """Un décalage appliqué à un objet date ne peut pas produire un 31 février
    — mais le rendu, lui, pourrait. On le vérifie sur une année bissextile."""
    assert dt.date.fromisoformat(sub(m, "2024-02-29"))


def test_it_is_deterministic_within_a_scope(m):
    assert sub(m, "2026-02-03") == sub(m, "2026-02-03")


def test_another_scope_shifts_differently(tmp_path):
    un = sub(moteur(tmp_path, "project:un"), "2026-02-03")
    deux = sub(moteur(tmp_path, "project:deux"), "2026-02-03")
    assert un != deux, "le décalage ne dépend pas de la portée"


def test_two_dates_never_share_a_surrogate(m):
    jours = [f"2026-03-{j:02d}" for j in range(1, 29)]
    rendus = [sub(m, j) for j in jours]
    assert len(set(rendus)) == len(jours)


def test_a_span_holding_no_date_falls_back_and_that_is_a_RESIDUAL(m):
    """Sans date lisible, la valeur reste protégée — mais elle sort en MOT, et
    la nature n'est plus tenue.

    Cette assertion, écrite « c'est toujours protégé », a couvert un vrai
    défaut : `3 février 2026 à 14h32` ne se parsait pas non plus, sortait en
    nom d'hôte, et le modèle a cessé de pouvoir répondre « quand ». Vérifier la
    protection ne vérifie pas l'invariant — il fallait les deux, et le second
    était déjà écrit deux modules plus loin.

    Les formes entourées sont désormais couvertes (`test_dates_entourees.py`).
    Ce qui reste ici est le résidu nommé : un span sans aucune date dedans.
    """
    assert sub(m, "le jour de la Saint-Glinglin") != "le jour de la Saint-Glinglin"


# --------------------------------------------------------------------------- #
# Tour 11 — les formes qui retombaient en MOT
# --------------------------------------------------------------------------- #
from anonproxy.surrogates import dates as _dates  # noqa: E402


@pytest.mark.parametrize("ecrit,attendu", [
    ("3 fev 2020", dt.date(2020, 2, 3)),        # sans accent, abrégé
    ("3 fév. 2020", dt.date(2020, 2, 3)),       # abrégé avec point
    ("15 Sept 2020", dt.date(2020, 9, 15)),
    ("2020/03/15", dt.date(2020, 3, 15)),       # année d'abord
    ("March 3, 2020", dt.date(2020, 3, 3)),     # mois d'abord, anglophone
    ("Mar. 3 2020", dt.date(2020, 3, 3)),
    ("03/15/2020", dt.date(2020, 3, 15)),       # jour d'abord IMPOSSIBLE ici
])
def test_une_forme_de_date_reconnue_de_plus(ecrit, attendu):
    """Ces formes retombaient sur la substitution GÉNÉRIQUE, donc sortaient en
    MOT : le modèle recevait un nom d'hôte là où le document annonçait une
    date, et cessait de pouvoir répondre « quand ». Rien ne fuyait — c'est la
    nature du substitut qui était perdue (D1)."""
    lu = _dates.parse(ecrit)
    assert lu is not None, f"{ecrit!r} retombe encore en mot"
    assert lu[0] == attendu


@pytest.mark.parametrize("ecrit,decalage,attendu", [
    # Un nom COMPLET reste complet : la longueur se compare au mois de DÉPART,
    # pas à celui d'arrivée — sinon `March` devient `Janua`.
    ("15 March 2020", 321, "30 January 2021"),
    ("15 mars 2020", 321, "30 janvier 2021"),
    ("12 MARS 2020", 321, "27 JANVIER 2021"),
    # Une ABRÉVIATION reste une abréviation, de la même longueur.
    ("3 fev 2020", 321, "20 déc 2020"),
    ("3 fév. 2020", 321, "20 déc. 2020"),
    ("Mar. 3 2020", 321, "Jan. 18 2021"),
    ("March 3, 2020", 321, "January 18, 2021"),
    # Les formes numériques gardent leur séparateur et leur ordre.
    ("2020/03/15", 321, "2021/01/30"),
    ("03/15/2020", 321, "01/30/2021"),
    ("15/03/2020", 321, "30/01/2021"),
    # `1er` ne vaut qu'au premier du mois.
    ("1er janvier 2020", 31, "1er février 2020"),
    ("1er janvier 2020", 321, "17 novembre 2020"),
])
def test_la_forme_d_ecriture_survit_au_decalage(ecrit, decalage, attendu):
    """D1 : l'opérateur et le modèle doivent lire une date écrite comme celle
    qu'ils ont remplacée."""
    jour, rendre = _dates.parse(ecrit)
    assert rendre(jour + dt.timedelta(days=decalage)) == attendu


@pytest.mark.parametrize("ecrit", [
    "3 jui 2020",      # juin ou juillet : deviner fabriquerait une date fausse
    "15/03/20",        # année sur deux chiffres : le siècle est un pari
    "32/01/2020",      # pas une date
    "3 ma 2020",       # deux lettres : mars, mai
])
def test_ce_qui_reste_ambigu_n_est_pas_deviné(ecrit):
    """L'unicité d'une abréviation est VÉRIFIÉE, jamais supposée. Ce qui n'est
    pas reconnu retombe en mot — visible, et c'est le résidu documenté."""
    assert _dates.parse(ecrit) is None
