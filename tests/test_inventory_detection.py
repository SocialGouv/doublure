"""L'inventaire PRIME — y compris au moment de la DÉTECTION.

Le moteur appliquait bien « allowlist MOINS inventaire ». Mais le service de
détection écarte un span couvert par une entrée EXACTE avant de le renvoyer :
le token n'atteignait jamais le moteur, et l'inventaire ne pouvait pas le
refermer. La protection existait et n'agissait pas.

Elle échouait exactement là où elle sert : sur les mots génériques que
l'allowlist ouvre (`monitoring`) et qu'un opérateur déclare siens parce qu'une
de ses machines porte ce nom.

Le test précédent montait le MOTEUR comme la production le monte — pas le
détecteur. C'est le motif du test complaisant, remonté d'une couche : il prouve
la moitié de la chaîne et laisse l'autre se tromper.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
WRAPPER = RACINE / "services" / "anonshield" / "wrapper" / "app.py"

#: Entrée EXACTE de l'allowlist : un namespace standard, public par défaut.
MOT_OUVERT = "monitoring"
TEXTE = f"le namespace {MOT_OUVERT} est en panne"


@pytest.fixture(scope="module")
def wrapper():
    """Importé par CHEMIN : la frontière D7 interdit une dépendance de code
    entre les deux côtés, mais un test peut charger le module pour vérifier la
    règle qui, elle, est dupliquée de part et d'autre."""
    if not WRAPPER.exists():
        pytest.skip("wrapper AnonShield absent")
    spec = importlib.util.spec_from_file_location("_wrapper_inventaire", WRAPPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # dépendances du service absentes
        pytest.skip(f"wrapper non importable : {exc}")
    return module


def juge(wrapper, texte: str, valeur: str, etype: str | None = None):
    """Rejoue la décision RÉELLE du service, avec l'inventaire que le service
    chargerait — pas une réécriture de la règle dans le test."""
    exact, motifs, types, motifs_types = wrapper._load_allowlist(
        wrapper.ALLOWLIST_FILE)
    debut = texte.index(valeur)
    span = {"value": valeur, "start": debut, "end": debut + len(valeur),
            "type": etype}
    return wrapper._raison_publique(texte, span, exact, motifs, types,
                                    motifs_types, wrapper._load_inventory())


@pytest.fixture
def inventaire(monkeypatch, tmp_path):
    fichier = tmp_path / "inventory.txt"
    fichier.write_text(f"{MOT_OUVERT}\nacmecorp\n", encoding="utf-8")
    monkeypatch.setenv("ANON_INVENTORY_FILE", str(fichier))
    return fichier


def test_sans_inventaire_le_mot_ouvert_est_bien_public(wrapper):
    """Le pendant : sans lui, le test suivant ne prouverait rien."""
    assert juge(wrapper, TEXTE, MOT_OUVERT, "HOSTNAME") is not None


def test_un_nom_declare_a_nous_n_est_plus_ecarte(wrapper, inventaire):
    assert juge(wrapper, TEXTE, MOT_OUVERT, "HOSTNAME") is None


def test_un_segment_declare_protege_le_compose(wrapper, inventaire):
    """Reconnu par SEGMENTS : `acmecorp` couvre les valeurs composites, qui
    n'ont aucune forme commune."""
    texte = "image registry.k8s.io/acmecorp-billing:v2"
    assert juge(wrapper, texte, "registry.k8s.io/acmecorp-billing", "URL") is None


def test_un_inventaire_demande_et_introuvable_est_une_erreur(wrapper, monkeypatch, tmp_path):
    """Le lire comme vide rendrait publics les noms qu'il devait fermer."""
    monkeypatch.setenv("ANON_INVENTORY_FILE", str(tmp_path / "absent.txt"))
    with pytest.raises(FileNotFoundError):
        wrapper._load_inventory()


def test_les_deux_cotes_de_la_frontiere_repondent_pareil(wrapper, inventaire):
    """La LISTE est unique, le parseur est dupliqué : c'est ce qui doit être
    vérifié, sinon les deux moitiés du système lisent la même ligne
    différemment."""
    from anonproxy.allowlist import DEFAULT_ALLOWLIST
    from anonproxy.proxy.app import predicat_public

    moteur_public = predicat_public(DEFAULT_ALLOWLIST, inventaire)
    for valeur, etype in ((MOT_OUVERT, "HOSTNAME"),
                          ("acmecorp-billing", "HOSTNAME"),
                          ("cert-manager", "HOSTNAME"),
                          ("localhost", "HOSTNAME")):
        texte = f"valeur {valeur} dans une phrase"
        detection_publique = juge(wrapper, texte, valeur, etype) is not None
        assert detection_publique == moteur_public(valeur, etype), valeur
