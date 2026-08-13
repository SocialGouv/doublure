"""Granulaire pour restaurer, grossier pour arbitrer.

Router les segments de chemin par le coffre était nécessaire : sans entrée
individuelle, un chemin COMPOSÉ par le modèle ne se restaure pas, et `Read`
échouait. Mais chaque segment se mettait aussi à poser sa propre question :
la file est passée de 205 à 267, dont 62 pour des morceaux que personne n'a
jamais désignés à l'agent.

L'unité que l'opérateur reconnaît est le CHEMIN, pas chacun de ses segments.
Un type que le moteur DÉCOUPE lui-même dans une valeur composite va donc au
coffre — la restauration en dépend — sans entrer dans la file.

C'est la même distinction que pour les attributs partagés (`_SUBNET_V4`,
`_ZONE`), à ceci près qu'eux sont aussi exclus de la vue de restauration :
un segment, lui, doit y rester.
"""
from __future__ import annotations

import pytest

from anonproxy.policy import Policy
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "f6" * 32
PROJET = "/home/ada/lab/ai/anonproxy-demo"


@pytest.fixture
def moteur(tmp_path):
    politique = Policy(racine=tmp_path / "pol", master_key=MASTER,
                       scope_key="project:g")
    moteur = SurrogateEngine(
        vault=Vault(tmp_path / "v.db", master_key=MASTER), master_key=MASTER,
        scope_key="project:g", policy=politique, projet=PROJET)
    return moteur, politique


def types_en_file(politique) -> list[str]:
    return [q["type"] for q in politique.questions()]


def test_un_chemin_pose_UNE_question(moteur):
    """Et pas une par segment."""
    m, politique = moteur
    m.substitute_value("FILE_PATH", f"{PROJET}/infra/inventaire.md")
    assert types_en_file(politique).count("PATH_SEGMENT") == 0
    assert types_en_file(politique).count("FILE_PATH") == 1


def test_les_segments_restent_restaurables(moteur):
    """Le contrepoids : ne pas poser la question ne veut pas dire ne pas
    enregistrer. Sans entrée de coffre, un chemin composé par le modèle
    redevient illisible — c'est le défaut qui a cassé `Read`."""
    m, _ = moteur
    faux = m.substitute_value("FILE_PATH", f"{PROJET}/infra/inventaire.md")
    vue = m.surrogates_view()
    compose = faux.replace("inventaire.md", "incident-4218.md")
    restaure = compose
    for f, reel in sorted(vue.items(), key=lambda kv: -len(kv[0])):
        restaure = restaure.replace(f, reel)
    assert restaure == f"{PROJET}/infra/incident-4218.md", restaure


def test_les_autres_types_posent_toujours_leur_question(moteur):
    """Le correctif ne doit pas faire taire la file en général."""
    m, politique = moteur
    m.substitute_value("HOSTNAME", "db-01.acme.internal")
    m.substitute_value("EMAIL_ADDRESS", "alice@acme.corp")
    assert set(types_en_file(politique)) == {"HOSTNAME", "EMAIL_ADDRESS"}
