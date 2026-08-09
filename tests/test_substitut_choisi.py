"""L'opérateur CHOISIT un substitut — et le passé reste restaurable.

Deux invariants s'affrontent ici, et aucun ne cède.

D6, l'injectivité : deux réels ne partagent jamais un substitut. Un choix qui
prendrait un substitut déjà attribué rendrait la restauration ambiguë, et
l'ambiguïté se résoudrait en SILENCE — le pire mode d'échec de ce système.

Et la restauration de ce qui est DÉJÀ parti : l'ancien substitut a réellement
été envoyé chez Anthropic. L'effacer ferait relire au modèle un nom qu'il a
lui-même reçu, sans que rien ne le signale. Il est donc démoté, jamais oublié.
"""
from __future__ import annotations

import pytest

from anonproxy.vault import PREFIXE_ANCIEN, SurrogateConflict, Vault

MASTER = "e5" * 32
SCOPE = "project:choisi"
HOTE = "db-master-01.acme.internal"


@pytest.fixture
def coffre(tmp_path):
    return Vault(tmp_path / "v.db", master_key=MASTER)


def test_l_operateur_impose_son_substitut(coffre):
    coffre.bind(SCOPE, "HOSTNAME", HOTE, "glacier-vault10.lamna.internal")
    assert coffre.rebind(SCOPE, "HOSTNAME", HOTE, "srv-choisi.exemple.internal") \
        == "srv-choisi.exemple.internal"
    assert coffre.get_surrogate(SCOPE, "HOSTNAME", HOTE) == "srv-choisi.exemple.internal"


def test_l_ancien_substitut_reste_restaurable(coffre):
    """Il est déjà parti : l'oublier casse la restauration de l'existant."""
    coffre.bind(SCOPE, "HOSTNAME", HOTE, "glacier-vault10.lamna.internal")
    coffre.rebind(SCOPE, "HOSTNAME", HOTE, "srv-choisi.exemple.internal")
    assert coffre.get_real(SCOPE, "glacier-vault10.lamna.internal") == HOTE
    # …et la VUE du walker le porte aussi, sans quoi le sens entrant l'ignore.
    assert coffre.view(SCOPE)["glacier-vault10.lamna.internal"] == HOTE


def test_l_ancien_substitut_reste_reserve(coffre):
    """D6 vaut sur le passé : personne d'autre ne peut le reprendre."""
    coffre.bind(SCOPE, "HOSTNAME", HOTE, "glacier-vault10.lamna.internal")
    coffre.rebind(SCOPE, "HOSTNAME", HOTE, "srv-choisi.exemple.internal")
    with pytest.raises(SurrogateConflict):
        coffre.bind(SCOPE, "HOSTNAME", "autre.acme.internal",
                    "glacier-vault10.lamna.internal")


def test_un_substitut_deja_pris_est_refuse(coffre):
    """On refuse, on n'écrase pas : l'ambiguïté ne se répare pas après coup."""
    coffre.bind(SCOPE, "HOSTNAME", HOTE, "un.exemple.internal")
    coffre.bind(SCOPE, "HOSTNAME", "autre.acme.internal", "deux.exemple.internal")
    with pytest.raises(SurrogateConflict):
        coffre.rebind(SCOPE, "HOSTNAME", HOTE, "deux.exemple.internal")
    # la liaison d'origine est intacte : un refus ne laisse pas de dégât
    assert coffre.get_surrogate(SCOPE, "HOSTNAME", HOTE) == "un.exemple.internal"


def test_redemander_le_meme_substitut_est_sans_effet(coffre):
    coffre.bind(SCOPE, "HOSTNAME", HOTE, "un.exemple.internal")
    assert coffre.rebind(SCOPE, "HOSTNAME", HOTE, "un.exemple.internal") \
        == "un.exemple.internal"
    assert coffre.get_real(SCOPE, "un.exemple.internal") == HOTE


def test_choisir_pour_une_valeur_inconnue_la_lie(coffre):
    assert coffre.rebind(SCOPE, "HOSTNAME", HOTE, "neuf.exemple.internal") \
        == "neuf.exemple.internal"
    assert coffre.get_real(SCOPE, "neuf.exemple.internal") == HOTE


def test_deux_changements_successifs_gardent_toute_la_chaine(coffre):
    coffre.bind(SCOPE, "HOSTNAME", HOTE, "un.exemple.internal")
    coffre.rebind(SCOPE, "HOSTNAME", HOTE, "deux.exemple.internal")
    coffre.rebind(SCOPE, "HOSTNAME", HOTE, "trois.exemple.internal")
    vue = coffre.view(SCOPE)
    for substitut in ("un.exemple.internal", "deux.exemple.internal",
                      "trois.exemple.internal"):
        assert vue[substitut] == HOTE, substitut


def test_les_attributs_partages_restent_hors_de_la_vue(coffre):
    """La démotion ne doit pas rouvrir ce que la vue exclut à dessein.

    Un attribut partagé résolu permettrait de reconstituer un hôte fictif
    inventé par le modèle en hôte réel (D5). Le préfixe historique est admis
    dans la vue ; celui des attributs partagés ne l'est pas.
    """
    coffre.bind(SCOPE, "_ZONE", "acme.internal", "lamna.internal")
    assert "lamna.internal" not in coffre.view(SCOPE)
    assert "lamna.internal" in coffre.view(SCOPE, include_internal=True)


def test_le_prefixe_historique_sort_de_l_unicite(coffre):
    """Le mécanisme lui-même : sans cette exemption, rien n'est possible."""
    assert PREFIXE_ANCIEN.startswith("_")
