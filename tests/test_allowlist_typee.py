"""Une entrée d'allowlist peut être limitée à des TYPES d'entité.

`to`, `run`, `code`, `error`, `low`, `high` sortent en FILE_PATH ou en
ORGANIZATION sur de la prose, et chacun coûte une question d'arbitrage. Les
déclarer publics tout court était une fuite : une machine réellement nommée
`code` sortait alors verbatim en HOSTNAME. L'allowlist était type-agnostique
par construction — elle répondait « cette valeur est publique », jamais
« publique QUAND elle est un chemin de fichier ».

D'où la portée par TYPE :

    code                              -> public partout (entrée ordinaire)
    types:FILE_PATH,ORGANIZATION code -> public SEULEMENT sous ces types

Le sens de la garde compte : sans type connu, une entrée typée ne s'applique
PAS. Un appelant qui ne sait pas de quoi il parle ne peut pas ouvrir — c'est le
défaut fermé, et c'est ce qui rend l'ajout de mots courants tenable.

Le parseur est dupliqué de part et d'autre de la frontière D7 (ici et dans le
service de détection) : c'est la LISTE qui est maintenue une fois, pas le code
qui la lit. Une nouvelle forme de ligne doit donc être écrite deux fois — le
prix est connu et assumé (dix lignes contre une dépendance de licence).
"""
from __future__ import annotations

import pytest

from anonproxy.allowlist import Allowlist

FICHIER = """\
# entrée ordinaire : publique pour tous les types
localhost
# entrées TYPÉES : publiques seulement sous ces types
types:FILE_PATH,ORGANIZATION code
types:FILE_PATH,ORGANIZATION run
types:FILE_PATH re:[\\w-]+\\.(md|txt)
"""


@pytest.fixture
def liste(tmp_path):
    chemin = tmp_path / "allowlist.txt"
    chemin.write_text(FICHIER, encoding="utf-8")
    return Allowlist.load(chemin)


def test_une_entree_typee_vaut_sous_son_type(liste):
    assert liste("code", "FILE_PATH")
    assert liste("code", "ORGANIZATION")


def test_une_entree_typee_ne_vaut_pas_ailleurs(liste):
    """Le cas mesuré : une machine réellement nommée `code`."""
    assert not liste("code", "HOSTNAME")
    assert not liste("code", "URL")
    assert not liste("code", "SERVICE_ACCOUNT")


def test_sans_type_connu_une_entree_typee_ne_s_applique_pas(liste):
    """Fail-closed : qui ne sait pas de quoi il parle n'ouvre rien."""
    assert not liste("code")
    assert not liste.is_exact("code")


def test_une_entree_ordinaire_reste_valable_partout(liste):
    assert liste("localhost")
    assert liste("localhost", "HOSTNAME")
    assert liste("localhost", "FILE_PATH")


def test_une_regle_de_forme_se_type_aussi(liste):
    assert liste("README.md", "FILE_PATH")
    assert not liste("README.md", "HOSTNAME")


def test_la_liste_du_depot_reste_lisible():
    """Le fichier réel se charge, et ses entrées non typées ne changent pas."""
    reelle = Allowlist.load()
    assert reelle("localhost", "HOSTNAME")
    assert reelle("10.0.0.0/8", "IP_ADDRESS")
    assert not reelle("db-01.acme.internal", "HOSTNAME")
