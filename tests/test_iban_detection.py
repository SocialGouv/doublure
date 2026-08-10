"""Un IBAN doit être DÉTECTÉ comme un IBAN, sinon rien d'autre ne s'applique.

Le moteur savait fabriquer un IBAN fictif bien formé. Il ne servait à rien :
interrogé sur la ligne du ticket, le détecteur ne rend AUCUN `IBAN_CODE`.

    CREDIT_CARD    "3000 6000 0112 3456"   0.7
    PHONE_NUMBER   "3000 6000 0112"        0.6

Deux conséquences, dont la seconde est une fuite :

1. La branche `IBAN_CODE` du moteur n'est jamais atteinte — d'où le « jeton
   hexadécimal au milieu » que le modèle a signalé trois sessions de suite.
2. Le span ne couvre que le MILIEU. `FR76` et le groupe final sortent EN
   CLAIR — or les deux derniers chiffres d'un IBAN français sont la clé RIB et
   ceux qui précèdent une partie du numéro de compte. Un identifiant financier
   part donc partiellement non substitué, et rien ne le compte.

La leçon vaut au-delà de l'IBAN : **un substitut bien formé ne protège rien si
la détection ne voit pas l'entité.** Le moteur et le détecteur se valident
séparément, et les tests du moteur passaient au vert pendant que la valeur
sortait à moitié en clair.

`config/custom_patterns.json` est le point d'extension prévu par le plan (§6),
sur terrain neutre, lu par le service de détection. Ce test valide le MOTIF —
la couverture de bout en bout demande un redémarrage du détecteur.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

MOTIFS = Path(__file__).resolve().parents[1] / "config" / "custom_patterns.json"

IBANS = [
    "FR76 3000 6000 0112 3456 7890 189",
    "FR7630006000011234567890189",
    "DE89 3704 0044 0532 0130 00",
    "GB33BUKB20201555555555",
    "BE68 5390 0754 7034",
    "NO93 8601 1117 947",
]

#: Ce qui ne doit PAS être pris pour un IBAN — un faux positif ici substitue
#: une référence technique et casse la lecture du modèle.
PAS_DES_IBANS = [
    "HTTP 200 OK",
    "SHA256 abcd",
    "v1.2 3456",
    "AB12",
]


@pytest.fixture(scope="module")
def motif_iban():
    entrees = json.loads(MOTIFS.read_text(encoding="utf-8"))
    motifs = [e["pattern"] for e in entrees if e.get("entity_type") == "IBAN_CODE"]
    assert motifs, "aucun motif IBAN_CODE dans config/custom_patterns.json"
    return re.compile("|".join(f"(?:{m})" for m in motifs))


@pytest.mark.parametrize("iban", IBANS)
def test_un_iban_est_reconnu_en_entier(motif_iban, iban):
    """En ENTIER : un span partiel laisse sortir le reste en clair."""
    trouve = motif_iban.search(iban)
    assert trouve is not None, iban
    assert trouve.group(0).strip() == iban, trouve.group(0)


@pytest.mark.parametrize("texte", PAS_DES_IBANS)
def test_ce_qui_n_est_pas_un_iban_ne_matche_pas(motif_iban, texte):
    assert motif_iban.search(texte) is None, texte


def test_le_motif_couvre_l_iban_dans_une_phrase(motif_iban):
    phrase = "Dossier ouvert le 12 mars 2019, compte FR76 3000 6000 0112 3456 7890 189."
    trouve = motif_iban.search(phrase)
    assert trouve is not None
    assert trouve.group(0).strip() == "FR76 3000 6000 0112 3456 7890 189"


def test_le_type_n_est_pas_public():
    """Un type absent de la table de classes tomberait dans le défaut : on
    vérifie qu'`IBAN_CODE` n'est pas rendu PUBLIC par accident."""
    from anonproxy.surrogates.classes import DataClass, class_of
    assert class_of("IBAN_CODE") is not DataClass.PUBLIC
