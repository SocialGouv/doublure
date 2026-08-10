"""Pourquoi les mots courants ne sont PAS dans l'allowlist.

Mesuré en session : `to`, `fire`, `the`, `code`, `run`, `png` sortent en
FILE_PATH, `low` et `medium` en ORGANIZATION. Chacun coûte une question
d'arbitrage, et il y en avait 248 pour une quinzaine de légitimes. La tentation
est donc forte de les déclarer publics.

Ils l'ont été, une heure durant, et la revue adversariale a montré le prix :
une machine RÉELLEMENT nommée `code` — VS Code Server, Gitea, une convention de
cluster — sortait alors VERBATIM en HOSTNAME. `https://code/api/customer/…`
laissait l'hôte en clair, sans entrée de coffre ni substitut non résolu : rien
à compter.

**L'allowlist est TYPE-AGNOSTIQUE par construction.** Elle répond « cette
valeur est publique », pas « cette valeur est publique QUAND elle est un chemin
de fichier ». Elle ne peut donc pas distinguer le mot de la machine.

Le contrepoids envisagé — l'inventaire, qui répond « ce nom est à nous » et qui
prime — est VIDE par défaut : un dépôt neuf n'a aucune protection sur ces noms.
Faire dépendre la fermeture d'un fichier que l'opérateur doit penser à écrire,
c'est la même inversion que l'anti-patron §7.

Fermer ce bruit demande une allowlist TYPÉE, plus la mesure de la file
d'arbitrage — que seul l'opérateur peut faire, elle rend des valeurs réelles.
En attendant : **une question d'arbitrage se voit, une fuite d'hôte ne se voit
pas.**

Ce fichier existe pour que la tentation ne se reprenne pas sans le prix.
"""
from __future__ import annotations

import pytest

from anonproxy.allowlist import Allowlist


@pytest.fixture(scope="module")
def public():
    return Allowlist.load()


@pytest.mark.parametrize("mot", [
    "to", "the", "a", "an", "and", "or", "not", "if", "for", "with", "from",
    "run", "code", "fire", "text", "error", "warning", "debug",
    "png", "jpg", "svg", "low", "medium", "high",
])
def test_un_mot_courant_n_est_pas_public(mot, public):
    """Chacun coûte une question d'arbitrage — et c'est le prix à payer tant
    que l'allowlist ne sait pas de quel TYPE elle parle."""
    assert not public(mot), (
        f"{mot!r} rendu public : une machine portant ce nom sortirait en clair")


def test_le_cas_qui_a_tranche(public):
    """Le cas mesuré : l'hôte d'une URL est justement un mot courant."""
    assert not public("code")
    assert not public("https://code/api/customer/acme-billing-2025-nda/export")
