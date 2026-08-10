"""Un numéro de carte a une SOMME DE CONTRÔLE, ou n'en est pas un.

Mesuré en session, quatre fois de suite : le compte
`FR76 3000 6000 0112 3456 7890 189` sortait en blob. Le détecteur voyait bien
l'IBAN entier (score 1.00), mais aussi un `CREDIT_CARD` sur ses groupes du
milieu (0.70) — seize chiffres par groupes de quatre, la forme exacte d'une
carte.

L'arbitrage de recouvrement met les SECRETS en premier « absolument, même
quand ils sont plus courts ou moins bien scorés » : c'est la garde D4, et elle
est juste. `CREDIT_CARD` est un secret, il gagnait donc, déchirait l'IBAN par
le milieu, et les fragments restants (`FR76`, `7890 189`) étaient substitués
chacun de leur côté.

La faute n'est ni dans l'arbitrage ni dans la classification de l'IBAN : elle
est dans le SPAN. `3000600001123456` échoue au test de Luhn — une carte en
porte une par définition (ISO/IEC 7812). Ce n'est pas une carte.

**On n'écarte que ce qu'un autre span COUVRE déjà.** Sinon la règle
deviendrait un chemin de fuite : une vraie carte dont le span est mal borné
échouerait à Luhn et sortirait en clair. Contenue, elle reste substituée par
le span qui la contient — on ne perd rien, on cesse seulement de déchirer.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
WRAPPER = RACINE / "services" / "anonshield" / "wrapper" / "app.py"


@pytest.fixture(scope="module")
def wrapper():
    if not WRAPPER.exists():
        pytest.skip("wrapper AnonShield absent")
    spec = importlib.util.spec_from_file_location("_wrapper_luhn", WRAPPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        pytest.skip(f"wrapper non importable : {exc}")
    return module


def span(etype, start, end, value, score=0.7):
    return {"type": etype, "start": start, "end": end, "value": value,
            "score": score}


IBAN = span("IBAN_CODE", 0, 33, "FR76 3000 6000 0112 3456 7890 189", 1.0)
CARTE_FAUSSE = span("CREDIT_CARD", 5, 24, "3000 6000 0112 3456")
CARTE_VRAIE = span("CREDIT_CARD", 5, 24, "4111 1111 1111 1111")


def test_une_fausse_carte_contenue_est_ecartee(wrapper):
    gardes = wrapper._ecarter_cartes_invalides([IBAN, CARTE_FAUSSE])
    assert CARTE_FAUSSE not in gardes
    assert IBAN in gardes


def test_une_vraie_carte_contenue_est_gardee(wrapper):
    """Luhn valide : c'est une carte, elle doit gagner l'arbitrage D4 même
    contenue dans un span plus long."""
    gardes = wrapper._ecarter_cartes_invalides([IBAN, CARTE_VRAIE])
    assert CARTE_VRAIE in gardes


def test_une_fausse_carte_NON_contenue_est_gardee(wrapper):
    """Le garde-fou : rien n'est écarté qui ne soit déjà couvert. Une vraie
    carte au span mal borné échouerait à Luhn — la laisser tomber la ferait
    sortir EN CLAIR, et c'est le seul mode d'échec invisible du système."""
    seule = span("CREDIT_CARD", 0, 19, "3000 6000 0112 3456")
    assert wrapper._ecarter_cartes_invalides([seule]) == [seule]


def test_les_autres_types_ne_sont_pas_touches(wrapper):
    autres = [IBAN, span("HOSTNAME", 6, 12, "db-01"),
              span("PHONE_NUMBER", 5, 19, "3000 6000 0112", 0.6)]
    assert wrapper._ecarter_cartes_invalides(autres) == autres
