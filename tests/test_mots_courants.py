"""Les mots courants sont publics SOUS LEUR TYPE, et nulle part ailleurs.

Mesuré en session : `to`, `fire`, `the`, `code`, `run`, `png` sortent en
FILE_PATH, `low` et `medium` en ORGANIZATION. Chacun coûte une question
d'arbitrage, et il y en avait des centaines pour une poignée de légitimes.

Ils ont d'abord été déclarés publics TOUT COURT, et la revue a montré le prix :
une machine réellement nommée `code` — VS Code Server, Gitea, une convention de
cluster — sortait alors VERBATIM en HOSTNAME, sans entrée de coffre ni
substitut non résolu. Rien à compter.

D'où la portée par TYPE. Deux gardes, et il faut les deux :

- une entrée typée ne vaut QUE sous ses types ;
- sans type connu, elle ne vaut PAS DU TOUT — qui ne sait pas de quoi il parle
  n'ouvre rien.

`ORGANIZATION` est le type qui attrape les raisons sociales : n'y déclarer que
des mots-outils et des niveaux. `code`, `fire`, `text` n'y figurent pas — ce
sont des noms d'entreprise plausibles.
"""
from __future__ import annotations

import pytest

from anonproxy.allowlist import Allowlist


@pytest.fixture(scope="module")
def public():
    return Allowlist.load()


MOTS_OUTILS = ["to", "the", "a", "an", "and", "or", "not", "if", "for",
               "with", "from", "low", "medium", "high"]
TERMES = ["run", "code", "fire", "text", "error", "warning", "debug",
          "png", "jpg", "svg"]


@pytest.mark.parametrize("mot", MOTS_OUTILS + TERMES)
def test_un_mot_courant_est_lisible_en_chemin(mot, public):
    assert public(mot, "FILE_PATH"), f"{mot!r} substitué en FILE_PATH"


@pytest.mark.parametrize("mot", MOTS_OUTILS + TERMES)
def test_un_mot_courant_reste_protege_en_hote(mot, public):
    """Le cas qui a tranché : une machine réellement nommée `code`."""
    assert not public(mot, "HOSTNAME"), f"{mot!r} rendu public en HOSTNAME"
    assert not public(mot, "URL"), f"{mot!r} rendu public en URL"


@pytest.mark.parametrize("mot", MOTS_OUTILS + TERMES)
def test_sans_type_connu_rien_ne_s_ouvre(mot, public):
    """Fail-closed : c'est ce qui rend la liste tenable."""
    assert not public(mot), f"{mot!r} rendu public sans type"


@pytest.mark.parametrize("mot", TERMES)
def test_un_terme_technique_n_est_pas_ouvert_en_organisation(mot, public):
    """`Code`, `Fire`, `Text` sont des raisons sociales plausibles ; les
    mots-outils, non."""
    assert not public(mot, "ORGANIZATION"), f"{mot!r} ouvert en ORGANIZATION"


@pytest.mark.parametrize("mot", MOTS_OUTILS)
def test_un_mot_outil_est_ouvert_en_organisation(mot, public):
    assert public(mot, "ORGANIZATION")


@pytest.mark.parametrize("valeur", [
    "Acme", "Renault", "Dassault", "acmecorp",
    "code-billing-01", "run.acme.internal", "acme-low", "/home/jo/code",
])
def test_un_nom_propre_ou_compose_n_est_pas_ouvert(valeur, public):
    for etype in ("FILE_PATH", "ORGANIZATION", "HOSTNAME", None):
        assert not public(valeur, etype), f"{valeur!r} ouvert en {etype}"
