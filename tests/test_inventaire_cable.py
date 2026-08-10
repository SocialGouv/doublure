"""L'inventaire doit être BRANCHÉ, pas seulement défini.

`src/anonproxy/inventory.py` existait, avec ses tests, sa documentation et sa
place dans l'architecture — et AUCUN chemin de production ne l'importait. Un
opérateur qui déclarait `code` dans `config/inventory.txt` était convaincu
d'avoir remonté la protection, alors que rien ne lisait le fichier.

Ce n'est pas un oubli anodin : le commentaire de `config/allowlist.txt`
justifiait l'ajout d'une liste de MOTS COURANTS en s'appuyant sur ce
contrepoids. Une documentation qui décrit une protection inexistante est pire
que pas de documentation — elle fait prendre une décision d'ouverture sur une
garantie qui n'existe pas.

Le test qui accompagnait la liste vérifiait `Inventory.est_a_nous` EN
ISOLATION : il prouvait que la classe fonctionne, jamais que le système s'en
sert. C'est la définition d'un test complaisant. Celui-ci monte le prédicat
comme la PRODUCTION le monte.
"""
from __future__ import annotations

import pytest

from anonproxy.allowlist import DEFAULT_ALLOWLIST
from anonproxy.inventory import Inventory
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "f6" * 32


@pytest.fixture
def inventaire(tmp_path):
    fichier = tmp_path / "inventory.txt"
    fichier.write_text("monitoring\nacmecorp\n", encoding="utf-8")
    return fichier


def moteur(tmp_path, inventaire=None):
    """Monté exactement comme `proxy/app.py` le monte."""
    from anonproxy.proxy.app import predicat_public

    return SurrogateEngine(
        vault=Vault(tmp_path / "v.db", master_key=MASTER), master_key=MASTER,
        scope_key="project:inv",
        is_public=predicat_public(DEFAULT_ALLOWLIST, inventaire))


def test_un_nom_declare_a_nous_est_substitue(tmp_path, inventaire):
    """`monitoring` est dans l'allowlist comme namespace standard. Déclaré à
    nous, il redevient protégé — c'est tout l'intérêt de l'inventaire."""
    assert moteur(tmp_path, inventaire).substitute_value("HOSTNAME", "monitoring") \
        != "monitoring"


def test_sans_inventaire_le_mot_reste_lisible(tmp_path):
    """Le pendant : sans déclaration, `monitoring` est le namespace standard,
    et le substituer ne protège rien tout en coûtant une question."""
    assert moteur(tmp_path).substitute_value("HOSTNAME", "monitoring") \
        == "monitoring"


def test_l_inventaire_ne_touche_pas_au_reste(tmp_path, inventaire):
    """Il ne peut que REMONTER la protection : ce qu'il ne nomme pas garde
    exactement le comportement d'avant."""
    m = moteur(tmp_path, inventaire)
    assert m.substitute_value("HOSTNAME", "cert-manager") == "cert-manager"
    assert m.substitute_value("IP_ADDRESS", "10.0.0.0/8") == "10.0.0.0/8"
    assert m.substitute_value("HOSTNAME", "db-01.acme.internal") \
        != "db-01.acme.internal"


def test_un_segment_declare_protege_le_compose(tmp_path, inventaire):
    """L'inventaire reconnaît un nom par ses SEGMENTS : déclarer `acmecorp`
    protège `acmecorp-billing`, que l'allowlist n'aurait de toute façon pas
    ouvert — mais aussi les sous-parties d'une valeur composite."""
    inv = Inventory.load(inventaire)
    assert inv.est_a_nous("acmecorp-billing")
    assert not inv.est_a_nous("cert-manager")


def test_l_inventaire_reel_peut_vivre_hors_du_depot(monkeypatch, inventaire):
    """Le fichier nomme l'organisation et ses zones : le tenir dans l'arbre de
    travail, c'est le publier au premier `git add` distrait."""
    monkeypatch.setenv("ANON_INVENTORY_FILE", str(inventaire))
    assert Inventory.load().est_a_nous("acmecorp-billing")


def test_un_inventaire_demande_et_introuvable_est_une_erreur(monkeypatch, tmp_path):
    """Le lire comme vide rendrait publics les noms qu'il devait fermer, sans
    rien dire. Seule l'absence à l'emplacement PAR DÉFAUT est légitime."""
    monkeypatch.setenv("ANON_INVENTORY_FILE", str(tmp_path / "faute-de-frappe.txt"))
    with pytest.raises(FileNotFoundError):
        Inventory.load()

    monkeypatch.delenv("ANON_INVENTORY_FILE")
    with pytest.raises(FileNotFoundError):
        Inventory.load(tmp_path / "inexistant.txt")
