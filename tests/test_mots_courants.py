"""Pourquoi les mots courants ne sont PAS dans l'allowlist — deux fois.

`to`, `run`, `code`, `error`, `png`, `low`, `high` sortent en FILE_PATH ou en
ORGANIZATION sur de la prose, et chacun coûte une question d'arbitrage. La
tentation de les déclarer publics est forte, et elle a été suivie deux fois.

PREMIER ESSAI — publics tout court. Une machine réellement nommée `code` — VS
Code Server, Gitea, une convention de cluster — sortait alors VERBATIM en
HOSTNAME, sans entrée de coffre ni substitut non résolu. Rien à compter.

SECOND ESSAI — publics sous les seuls types FILE_PATH et ORGANIZATION. La
prémisse était que le TYPE sépare le mot de la machine. Elle est FAUSSE, et
c'est mesuré sur le détecteur réel :

    "reach code at port 8080"          -> FILE_PATH 'code'     (c'est un hôte)
    "server hostname: code"            -> FILE_PATH 'code'     (c'est un hôte)
    "consult with High Fidelity Corp"  -> ORGANIZATION 'High'  (raison sociale
                                          découpée en tokens par le NER)

Le type est lui-même une HEURISTIQUE, et elle échoue précisément sur les cas
ambigus — ceux pour lesquels on voulait la portée. La règle était déplacée, pas
fermée : `code` en position d'hôte sortait toujours en clair, et le nom d'une
entreprise composée (`High Fidelity`, `Low Latency`) partait par morceaux.

Le MÉCANISME de portée par type reste, il est sain ; c'est cette LISTE-là qui
ne peut pas s'en servir. Une question d'arbitrage se voit et se solde en un
geste ; une fuite d'hôte ne se voit jamais.
"""
from __future__ import annotations

import pytest

from anonproxy.allowlist import Allowlist

MOTS = ["to", "the", "a", "an", "and", "or", "not", "if", "for", "with",
        "from", "run", "code", "fire", "text", "error", "warning", "debug",
        "png", "jpg", "svg", "low", "medium", "high"]


@pytest.fixture(scope="module")
def public():
    return Allowlist.load()


@pytest.mark.parametrize("mot", MOTS)
def test_un_mot_courant_n_est_public_sous_aucun_type(mot, public):
    """Y compris FILE_PATH et ORGANIZATION : c'est là que le détecteur range
    une machine et une raison sociale quand le contexte est ambigu."""
    for etype in ("FILE_PATH", "ORGANIZATION", "HOSTNAME", "URL", None):
        assert not public(mot, etype), f"{mot!r} ouvert en {etype}"


def test_le_mecanisme_de_portee_reste_disponible(tmp_path):
    """Ce qui a échoué est la LISTE, pas le mécanisme : il reste utilisable
    pour une entrée dont le type, lui, est stable."""
    fichier = tmp_path / "a.txt"
    fichier.write_text("types:K8S_NAMESPACE demo-apps\n", encoding="utf-8")
    liste = Allowlist.load(fichier)
    assert liste("demo-apps", "K8S_NAMESPACE")
    assert not liste("demo-apps", "HOSTNAME")
    assert not liste("demo-apps")


def test_un_doublon_ordinaire_et_type_est_refuse(tmp_path):
    """L'entrée ordinaire gagnerait EN SILENCE et ouvrirait tous les types —
    exactement la fuite que la portée ferme. Un mainteneur qui ajoute la ligne
    sans voir l'autre doit être arrêté."""
    fichier = tmp_path / "a.txt"
    fichier.write_text("types:FILE_PATH code\ncode\n", encoding="utf-8")
    with pytest.raises(ValueError, match="portée de types"):
        Allowlist.load(fichier)

    fichier.write_text("code\ntypes:FILE_PATH code\n", encoding="utf-8")
    with pytest.raises(ValueError, match="sans"):
        Allowlist.load(fichier)
