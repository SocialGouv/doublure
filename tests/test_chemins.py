"""Un chemin est un CONTENANT : seul ce qui identifie y est substitué.

Écrit AVANT le code, parce que c'est une règle qui ÉLARGIT ce qui est public.
Le round 8 a payé la leçon : c'est la seule famille de règles dont l'échec est
une fuite SILENCIEUSE — pas de 400, pas de 503, pas d'entrée au coffre, rien à
compter. Tout le reste échoue bruyamment.

Ce qui identifie dans un chemin, c'est le NOM D'UTILISATEUR, et selon le
réglage le nom du PROJET. `/home` est sur toutes les machines du monde : le
masquer ne protège rien et coûte cher — le round 7 a mesuré ce prix, quand
`infra.md` transformé en faux domaine a fait tourner l'agent en rond jusqu'à
épuiser ses tours.
"""
from __future__ import annotations

import pytest

from anonproxy.modes import (CHEMINS_COMPLET, CHEMINS_UTILISATEUR,
                             CHEMINS_UTILISATEUR_PROJET)
from anonproxy.policy import Policy
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "d4" * 32
SCOPE = "project:chemins"


@pytest.fixture
def moteur(tmp_path):
    def build(chemins=CHEMINS_UTILISATEUR_PROJET):
        politique = Policy(racine=tmp_path / f"pol-{chemins}", master_key=MASTER,
                           scope_key=SCOPE)
        politique.definir_reglage("projet", "chemins", chemins)
        return SurrogateEngine(
            vault=Vault(tmp_path / f"{chemins}.db", master_key=MASTER),
            master_key=MASTER, scope_key=SCOPE, policy=politique)
    return build


def segments(chemin: str) -> list[str]:
    return [p for p in chemin.split("/") if p]


# --- ce qui doit RESTER ---------------------------------------------------- #

def test_la_racine_standard_reste(moteur):
    """`/home` existe sur toutes les machines : le masquer ne protège rien."""
    sortie = moteur().substitute_value("FILE_PATH", "/home/ada/example/test.md")
    assert sortie.startswith("/home/"), sortie


def test_le_nom_de_fichier_reste(moteur):
    """Masquer le nom de fichier empêche l'agent de retrouver le fichier."""
    sortie = moteur().substitute_value("FILE_PATH", "/home/ada/example/test.md")
    assert sortie.endswith("/test.md"), sortie


def test_le_chemin_relatif_dans_le_projet_reste(moteur):
    sortie = moteur().substitute_value(
        "FILE_PATH", "/home/ada/example/src/module/fichier.py")
    assert sortie.endswith("/src/module/fichier.py"), sortie


@pytest.mark.parametrize("racine", ["/usr", "/etc", "/var", "/opt", "/tmp", "/srv"])
def test_les_racines_systeme_restent(moteur, racine):
    sortie = moteur().substitute_value("FILE_PATH", f"{racine}/quelque/chose")
    assert sortie.startswith(racine + "/"), sortie


# --- ce qui doit être SUBSTITUÉ -------------------------------------------- #

def test_le_nom_d_utilisateur_est_substitue(moteur):
    """C'est la valeur qui identifie une personne. Elle sort toujours."""
    sortie = moteur().substitute_value("FILE_PATH", "/home/ada/example/test.md")
    assert "/ada/" not in sortie, sortie
    assert segments(sortie)[1] != "jo"


def test_le_projet_est_substitue_par_defaut(moteur):
    """`/home/ada/acme-nda/` : le segment projet peut nommer un client."""
    sortie = moteur().substitute_value("FILE_PATH", "/home/ada/acme-nda/notes.md")
    assert "acme-nda" not in sortie, sortie
    assert sortie.endswith("/notes.md"), sortie


def test_le_projet_reste_si_l_operateur_l_ouvre(moteur):
    """Réglage `utilisateur` : l'opérateur assume que le projet est anodin."""
    sortie = moteur(CHEMINS_UTILISATEUR).substitute_value(
        "FILE_PATH", "/home/ada/example/test.md")
    assert "/example/" in sortie, sortie
    assert segments(sortie)[1] != "jo"


def test_complet_substitue_tout(moteur):
    """L'ancien comportement reste atteignable : c'est le plus fermé."""
    sortie = moteur(CHEMINS_COMPLET).substitute_value(
        "FILE_PATH", "/home/ada/example/test.md")
    assert "home" not in sortie, sortie
    assert "test.md" not in sortie, sortie


# --- ce qui ne doit PAS s'élargir ------------------------------------------ #

def test_une_racine_inconnue_reste_entierement_substituee(moteur):
    """Forme non modélisée : on ferme. La liste des racines est FERMÉE.

    Sans cela, il suffirait d'inventer un premier segment pour que tout le
    chemin devienne public — exactement le défaut du round 8, où un radical
    trop permissif rendait publics des identifiants entiers.
    """
    sortie = moteur().substitute_value("FILE_PATH", "/donnees-client/acme/note.txt")
    assert "acme" not in sortie, sortie
    assert "note.txt" not in sortie, sortie


def test_un_chemin_relatif_reste_entierement_substitue(moteur):
    """Sans racine, rien ne dit où commence le projet : on ne devine pas."""
    sortie = moteur().substitute_value("FILE_PATH", "clients/acme-nda/notes.md")
    assert "acme-nda" not in sortie, sortie


def test_home_seul_n_expose_pas_d_utilisateur(moteur):
    assert moteur().substitute_value("FILE_PATH", "/home") == "/home"


def test_la_racine_seule_est_rendue_telle_quelle(moteur):
    assert moteur().substitute_value("FILE_PATH", "/") == "/"


# --- les invariants du moteur tiennent toujours ---------------------------- #

def test_le_meme_chemin_rend_le_meme_substitut(moteur):
    eng = moteur()
    a = eng.substitute_value("FILE_PATH", "/home/ada/example/test.md")
    b = eng.substitute_value("FILE_PATH", "/home/ada/example/test.md")
    assert a == b


def test_deux_utilisateurs_distincts_ne_partagent_pas_un_substitut(moteur):
    """D6 : l'injectivité vaut aussi sur la partie qu'on substitue encore."""
    eng = moteur()
    a = eng.substitute_value("FILE_PATH", "/home/ada/example/test.md")
    b = eng.substitute_value("FILE_PATH", "/home/marie/example/test.md")
    assert segments(a)[1] != segments(b)[1]
