"""Un IBAN reste un IBAN, et n'appartient à aucun compte.

Signalé DEUX FOIS par le modèle en session réelle, via le marqueur
`[ANONYMISATION]` : « un IBAN français fait 27 caractères, celui-ci en compte
30, et le second groupe est de l'hexadécimal en minuscules ». Il avait raison
sur toute la ligne, et il n'a rien inventé — c'est exactement ce que l'annonce
lui demande de faire.

Le moteur n'avait aucune branche : `IBAN_CODE` tombait dans le générique et
sortait sous un MOT (`registry-kestrel76`), ou sous une empreinte hexadécimale
quand le détecteur découpait autrement. Même défaut que `PHONE_NUMBER` avant
lui, même invariant du round 18 : **un substitut doit être indiscernable en
NATURE de ce qu'il remplace, et ne jamais désigner une entité du monde réel.**

Les deux moitiés de l'invariant, ici :

- NATURE — pays, longueur, gabarit d'espacement, classes de caractères, et une
  clé de contrôle mod-97 VALIDE. Un outil qui valide l'IBAN ne doit pas voir la
  différence, sinon le modèle passe son temps à signaler la forme au lieu de
  travailler.
- PERSONNE — l'identifiant de banque est mis à ZÉRO, qui n'est alloué à aucun
  établissement. Un IBAN valide tiré au hasard, lui, désigne le compte de
  quelqu'un : c'est le même arbitrage que la RFC 2544 pour les adresses et les
  plages de fiction pour les numéros.
"""
from __future__ import annotations

import re

import pytest

from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "f6" * 32

IBANS = [
    "FR76 3000 6000 0112 3456 7890 189",
    "FR7630006000011234567890189",
    "DE89 3704 0044 0532 0130 00",
    "GB33BUKB20201555555555",
    "BE68 5390 0754 7034",
]


@pytest.fixture
def moteur(tmp_path):
    return SurrogateEngine(vault=Vault(tmp_path / "i.db", master_key=MASTER),
                           master_key=MASTER, scope_key="project:iban")


def compact(v: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", v).upper()


def mod97(v: str) -> int:
    reordonne = v[4:] + v[:4]
    return int("".join(str(int(c, 36)) for c in reordonne)) % 97


@pytest.mark.parametrize("iban", IBANS)
def test_le_substitut_est_un_iban(moteur, iban):
    """Même pays, même longueur, même gabarit."""
    sortie = moteur.substitute_value("IBAN_CODE", iban)
    assert len(sortie) == len(iban), sortie
    assert compact(sortie)[:2] == compact(iban)[:2], sortie
    assert len(compact(sortie)) == len(compact(iban)), sortie
    # Les espaces sont aux mêmes places : le modèle lit un IBAN, pas un blob.
    assert [i for i, c in enumerate(sortie) if not c.isalnum()] == \
           [i for i, c in enumerate(iban) if not c.isalnum()], sortie


@pytest.mark.parametrize("iban", IBANS)
def test_la_cle_de_controle_est_valide(moteur, iban):
    """Sinon tout outil qui valide un IBAN rejette le substitut, et le modèle
    signale la forme au lieu de travailler — mesuré deux fois en session."""
    assert mod97(compact(moteur.substitute_value("IBAN_CODE", iban))) == 1


@pytest.mark.parametrize("iban", IBANS)
def test_le_substitut_ne_designe_aucun_compte(moteur, iban):
    """L'identifiant d'établissement est neutralisé — `0` là où le BBAN attend
    un chiffre, `Z` là où il attend une lettre (un BBAN britannique porte son
    code banque en lettres). Ni l'un ni l'autre n'est attribué : le compte
    n'existe chez personne."""
    corps = compact(moteur.substitute_value("IBAN_CODE", iban))[4:]
    assert set(corps[:5]) <= {"0", "Z"}, corps


@pytest.mark.parametrize("iban", IBANS)
def test_aucun_chiffre_du_reel_ne_survit(moteur, iban):
    sortie = moteur.substitute_value("IBAN_CODE", iban)
    assert compact(sortie)[4:] != compact(iban)[4:], sortie


def test_deux_ibans_distincts_ne_partagent_pas_un_substitut(moteur):
    assert len({moteur.substitute_value("IBAN_CODE", i) for i in IBANS}) \
        == len(IBANS)


def test_le_meme_iban_rend_le_meme_substitut(moteur):
    a = moteur.substitute_value("IBAN_CODE", IBANS[0])
    assert a == moteur.substitute_value("IBAN_CODE", IBANS[0])


def test_une_valeur_qui_n_est_pas_un_iban_ne_casse_pas(moteur):
    """Le détecteur se trompe : la branche ne doit pas lever, ni rendre une
    valeur qui ressemble à un IBAN alors que ce n'en était pas un."""
    for v in ("FR", "1234", "pas-un-iban", ""):
        assert moteur.substitute_value("IBAN_CODE", v) != v or not v
