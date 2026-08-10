"""Un numéro de téléphone reste un NUMÉRO, et n'appartient à personne.

Mesuré dans une session réelle : `PHONE_NUMBER` n'avait aucune branche, donc
un numéro sortait sous un MOT (`planner-tundra06`). Le modèle ne peut alors ni
le reconnaître, ni le formater, ni raisonner dessus — l'invariant du round 18,
« un substitut doit être indiscernable en NATURE de ce qu'il remplace ».

Le second volet est le même que pour les IP : un substitut ne doit désigner
AUCUNE entité du monde réel. Un numéro tiré au hasard sonne chez quelqu'un.
Les plages de fiction existent pour ça — 555-01xx aux États-Unis (RFC 3849 en
est l'équivalent v6), 06 39 98 xx xx et 01 99 00 xx xx en France (ARCEP).
"""
from __future__ import annotations

import re

import pytest

from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "f6" * 32
SCOPE = "project:tel"

NUMEROS = [
    "+33 6 12 34 56 78",
    "06 12 34 56 78",
    "0612345678",
    "+1 415 555 2671",
    "(415) 867-5309",
    "+44 20 7946 0958",
]


@pytest.fixture
def moteur(tmp_path):
    return SurrogateEngine(vault=Vault(tmp_path / "t.db", master_key=MASTER),
                           master_key=MASTER, scope_key=SCOPE)


@pytest.mark.parametrize("numero", NUMEROS)
def test_un_numero_reste_un_numero(moteur, numero):
    """Assez de chiffres pour être lu comme un numéro, et pas un mot."""
    sortie = moteur.substitute_value("PHONE_NUMBER", numero)
    assert sum(c.isdigit() for c in sortie) >= 8, sortie
    assert not re.search(r"[A-Za-z]", sortie), sortie


@pytest.mark.parametrize("numero", NUMEROS)
def test_la_forme_est_conservee(moteur, numero):
    """Longueur, indicatif et ponctuation : le modèle raisonne dessus."""
    sortie = moteur.substitute_value("PHONE_NUMBER", numero)
    assert sortie.startswith("+") == numero.startswith("+"), sortie
    assert len(sortie) == len(numero), sortie
    assert sum(c.isdigit() for c in sortie) == sum(c.isdigit() for c in numero)


#: Plages de FICTION réservées par les régulateurs — elles ne sonnent nulle
#: part. Vérifier un PRÉFIXE, et non une sous-chaîne quelconque : une
#: sous-chaîne peut apparaître par accident au milieu d'un vrai numéro, et le
#: test passerait alors sur un substitut qui appelle quelqu'un.
PLAGES_FICTIVES = re.compile(
    r"3363998\d*"        # France mobile, +33 6 39 98 xx xx (ARCEP)
    r"|063998\d*"        # France mobile, forme nationale
    r"|3319900\d*"       # France fixe, +33 1 99 00 xx xx
    r"|019900\d*"        # France fixe, forme nationale
    # NANP : c'est la LIGNE `01xx` de l'indicatif d'abonné `555` qui est
    # réservée, et elle l'est pour N'IMPORTE QUEL indicatif régional (FCC).
    # Le figer à `555` ne laissait que cent numéros — d'où l'indicatif variable.
    r"|1[2-9]\d\d55501\d*"   # NANP international, +1 AAA 555 01xx
    r"|[2-9]\d\d55501\d*"    # NANP, forme nationale
    r"|442079460\d*"     # Royaume-Uni, 020 7946 0xxx (drame, Ofcom)
    r"|447700900\d*"     # Royaume-Uni mobile, 07700 900xxx
    r"|210\d*"           # indicatif pays NON ATTRIBUÉ (E.164), repli
)


@pytest.mark.parametrize("numero", [
    "+49 30 12345678", "+81 3 1234 5678", "+7 495 123 45 67",
])
def test_un_pays_inconnu_ne_devient_pas_un_autre_pays(moteur, numero):
    """Le repli composait `555…` derrière le `+` : `+49 30 12345678` sortait en
    `+55 55 55014521`, et `+55` est le Brésil. Fabriquer un indicatif pays
    ATTRIBUÉ, c'est désigner le téléphone de quelqu'un — la faute même que le
    round 18 a corrigée sur les adresses. Sans plage de fiction connue pour ce
    pays, on part sur un indicatif NON ATTRIBUÉ : le numéro n'est plus
    plausible pour son pays (D1), mais il ne joint personne."""
    chiffres = re.sub(r"\D", "", moteur.substitute_value("PHONE_NUMBER", numero))
    assert chiffres.startswith("210"), chiffres


@pytest.mark.parametrize("numero", NUMEROS)
def test_le_substitut_ne_sonne_chez_personne(moteur, numero):
    """Une plage de FICTION, jamais un numéro attribuable.

    Même arbitrage que le round 18 sur les IP : varier des octets pour obtenir
    des adresses distinctes faisait sortir de l'espace réservé et atterrir sur
    le réseau de quelqu'un. Un numéro se raisonne pareil — sauf qu'ici il
    sonne chez cette personne, et que c'est le modèle qui propose de l'appeler.
    """
    chiffres = re.sub(r"\D", "", moteur.substitute_value("PHONE_NUMBER", numero))
    assert PLAGES_FICTIVES.fullmatch(chiffres), chiffres


@pytest.mark.parametrize("courts", [
    ["12345", "98765", "40404"],          # codes courts / postes
    ["+15", "+16", "+17"],                # indicatifs trop courts pour une plage
])
def test_deux_numeros_courts_ne_refusent_pas_la_requete(moteur, courts):
    """Plus court que sa plage de fiction, le numéro n'avait PLUS AUCUNE
    variation par tentative : le préfixe tronqué était constant, donc deux
    valeurs distinctes se disputaient un substitut et la seconde tombait en
    503. Un poste téléphonique est interne — il ne joint personne au-dehors,
    et sa co-existence avec un autre poste ne doit pas tuer la session."""
    rendus = {moteur.substitute_value("PHONE_NUMBER", n) for n in courts}
    assert len(rendus) == len(courts), rendus


def test_deux_numeros_distincts_ne_partagent_pas_un_substitut(moteur):
    sorties = {moteur.substitute_value("PHONE_NUMBER", n) for n in NUMEROS}
    assert len(sorties) == len(NUMEROS)


def test_le_meme_numero_rend_le_meme_substitut(moteur):
    a = moteur.substitute_value("PHONE_NUMBER", NUMEROS[0])
    b = moteur.substitute_value("PHONE_NUMBER", NUMEROS[0])
    assert a == b
