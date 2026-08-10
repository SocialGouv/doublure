"""Un span PARTIEL se juge sur le TOKEN auquel il appartient.

Le NER ne rend souvent que le domaine : `github.com` dans
`github.com/spf13/cobra`. L'allowlist, elle, connaît le chemin d'import
complet, pas l'hôte nu. Sans expansion, l'agent devient inutilisable — le plan
mesure 82 % de faux positifs sans allowlist.

Le wrapper testait donc « la valeur OU le token étendu ». Une revue
adversariale a signalé la faille de ce `ou` : un span `example.com` extrait de
`db.example.com` est publiquement allowlisté par sa VALEUR, si bien que le span
tombait et que l'hôte interne entier passait en clair.

J'ai corrigé en exigeant les DEUX — et c'était faux dans l'autre sens. Mesuré
en session réelle : `github.com/spf13/cobra`, `sigs.k8s.io/controller-runtime`,
`registry.k8s.io/kube-apiserver` et `docker.io/library/nginx:1.27-alpine` se
sont mis à sortir substitués, alors que le fichier les annonce publics. Le
modèle l'a signalé avec le marqueur, sans trancher, et il avait raison.

La bonne règle n'est ni « ou » ni « et » : **c'est le TOKEN ÉTENDU qui décide,
et lui seul.** Le span n'est qu'un fragment ; ce qui part sur le réseau, c'est
le token.

    span `github.com`  dans `github.com/spf13/cobra`  -> token public   -> écarté
    span `example.com` dans `db.example.com`          -> token NON public -> gardé

Les deux cas tombent juste, sans arbitrage supplémentaire.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
WRAPPER = RACINE / "services" / "anonshield" / "wrapper" / "app.py"


@pytest.fixture(scope="module")
def wrapper():
    """Importé par CHEMIN : la frontière D7 interdit une dépendance de code
    entre les deux côtés, mais un test peut charger le module pour vérifier la
    règle qui, elle, est dupliquée de part et d'autre."""
    if not WRAPPER.exists():
        pytest.skip("wrapper AnonShield absent")
    spec = importlib.util.spec_from_file_location("_wrapper_sous_test", WRAPPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # dépendances du service absentes
        pytest.skip(f"wrapper non importable : {exc}")
    return module


def juge(wrapper, texte: str, valeur: str, etype: str | None = None):
    """Rejoue la décision RÉELLE du service — la fonction qu'il appelle, pas
    une réécriture de sa règle dans le test. C'est toute la différence : la
    décision vivait en ligne dans l'endpoint, et un test qui la reformule
    passe au vert pendant que le service se trompe."""
    exact, motifs, types, motifs_types = wrapper._load_allowlist(
        wrapper.ALLOWLIST_FILE)
    debut = texte.index(valeur)
    span = {"value": valeur, "start": debut, "end": debut + len(valeur),
            "type": etype}
    return wrapper._raison_publique(texte, span, exact, motifs, types,
                                    motifs_types)


PUBLICS = [
    ("- module Go : github.com/spf13/cobra", "github.com"),
    ("- module Go : sigs.k8s.io/controller-runtime", "sigs.k8s.io"),
    ("- image : registry.k8s.io/kube-apiserver", "registry.k8s.io"),
    ("- base : docker.io/library/nginx:1.27-alpine", "docker.io"),
]


@pytest.mark.parametrize("texte,valeur", PUBLICS)
def test_un_span_partiel_dans_un_token_public_est_ecarte(wrapper, texte, valeur):
    assert juge(wrapper, texte, valeur) is not None, (texte, valeur)


SEGMENTS = [
    # Le round 7 avait ajouté la règle des noms de fichiers parce que `.md`
    # est le ccTLD de la Moldavie : un fichier Markdown cité dans un prompt
    # devenait un faux domaine, et l'agent ne retrouvait plus le fichier qu'on
    # lui désignait. Mesuré à nouveau en session : `infra/incident-4218.md`
    # sortait en `infra/zephyr-creek-4218.woodgrove-graphic.dev`.
    ("ouvre infra/incident-4218.md pour voir", "incident-4218.md"),
    ("le fichier docs/architecture.md decrit tout", "architecture.md"),
    ("charge config/settings.json au demarrage", "settings.json"),
]


@pytest.mark.parametrize("texte,valeur", SEGMENTS)
def test_un_segment_de_chemin_public_est_ecarte(wrapper, texte, valeur):
    """La barre oblique sépare des composants INDÉPENDANTS : `infra/` devant un
    nom de fichier laisse ce nom intact, là où `db.` devant un domaine en fait
    un AUTRE hôte. C'est cette différence que la règle doit voir."""
    assert juge(wrapper, texte, valeur) is not None, (texte, valeur)


SENSIBLES = [
    ("hote db.example.com en production", "example.com"),
    ("depot github.com/acmecorp/payments-api", "github.com/acmecorp/payments-api"),
    ("image registry.acmecorp.io/payments/api:4.2.1", "registry.acmecorp.io"),
    ("noeud node1.k8s.io.acme.internal", "k8s.io"),
]


@pytest.mark.parametrize("mot", ["code", "run", "error", "low", "png"])
def test_les_deux_parseurs_lisent_la_meme_liste_typee(wrapper, mot):
    """Le parseur est DUPLIQUÉ de part et d'autre de la frontière D7 : c'est la
    LISTE qui est maintenue une fois, pas le code qui la lit. Une nouvelle forme
    de ligne doit donc être écrite deux fois — et si les deux moitiés
    divergeaient, le détecteur et le moteur ne protégeraient pas la même chose,
    en silence. Ce test compare leurs verdicts sur le fichier RÉEL."""
    from anonproxy.allowlist import Allowlist
    notre = Allowlist.load()
    for etype, attendu in (("FILE_PATH", True), ("HOSTNAME", False),
                           (None, False)):
        cote_moteur = notre(mot, etype)
        cote_detecteur = juge(wrapper, f"voir {mot} ici", mot, etype) is not None
        assert cote_moteur is attendu, (mot, etype, "moteur")
        assert cote_detecteur is attendu, (mot, etype, "détecteur")


@pytest.mark.parametrize("texte,valeur", SENSIBLES)
def test_un_span_partiel_dans_un_token_sensible_est_garde(wrapper, texte, valeur):
    """Le sens que la revue avait raison de pointer : la valeur seule peut être
    publique alors que le token qui la contient ne l'est pas."""
    assert juge(wrapper, texte, valeur) is None, (texte, valeur)
