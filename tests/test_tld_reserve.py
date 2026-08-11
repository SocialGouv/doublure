"""Un domaine déjà RÉSERVÉ ne doit pas devenir un domaine réel.

Mesuré en session : `alice.dupont@acmecorp.example` sortait en
`isley-cameron.wren@parnell-alpine.co`. Le réel était sous `.example`, que la
RFC 2606 garantit à PERSONNE ; le substitut est sous `.co`, où
`parnell-alpine.co` peut appartenir à quelqu'un.

**La substitution rendait la valeur MOINS sûre qu'elle ne l'était.** C'est le
pire sens possible : non seulement on ne protège pas, mais on dégrade — et
c'est exactement l'invariant du round 18, « un substitut ne doit jamais
désigner une entité du monde réel ».

Ce n'est PAS l'arbitrage `domaines_fictifs` en attente, qui pèse la
plausibilité (D1) contre la garantie RFC 2606 pour les domaines ORDINAIRES.
Ici il n'y a rien à peser : le réel était déjà réservé, donc le rendre réservé
ne coûte AUCUNE plausibilité — `.example` est aussi crédible que l'original,
puisque l'original était `.example`. C'est un attribut déjà présent qu'on
préserve, comme « interne vs externe » et la co-appartenance /24 (§3.4).
"""
from __future__ import annotations

import pytest

from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.surrogates.lexicon import RESERVED_TLDS
from anonproxy.vault import Vault

MASTER = "f6" * 32

#: RFC 2606 : les TLD réservés, et les domaines de second niveau réservés.
RESERVES = [
    "acmecorp.example",
    "acme.test",
    "acme.invalid",
    "srv-01.acme.localhost",
    "portail.example.com",
    "mail.example.org",
]

ORDINAIRES = ["acmecorp.fr", "www.acme.com", "portail.acme.io"]


@pytest.fixture
def moteur(tmp_path):
    return SurrogateEngine(vault=Vault(tmp_path / "t.db", master_key=MASTER),
                           master_key=MASTER, scope_key="project:tld")


def tld(valeur: str) -> str:
    return valeur.rsplit("@", 1)[-1].rsplit(".", 1)[-1]


@pytest.mark.parametrize("hote", RESERVES)
def test_un_hote_deja_reserve_le_reste(moteur, hote):
    assert tld(moteur.substitute_value("HOSTNAME", hote)) in RESERVED_TLDS


@pytest.mark.parametrize("hote", RESERVES)
def test_une_adresse_sous_un_domaine_reserve_le_reste(moteur, hote):
    sortie = moteur.substitute_value("EMAIL_ADDRESS", f"alice.dupont@{hote}")
    assert tld(sortie) in RESERVED_TLDS, sortie


@pytest.mark.parametrize("hote", ORDINAIRES)
def test_un_domaine_ordinaire_reste_reserve_lui_aussi_par_defaut(moteur, hote):
    """Arbitrage rendu : le DÉFAUT ferme, y compris sans politique attachée.

    Cette attente était l'inverse — « sans réglage, la plausibilité l'emporte ».
    Tant que la condition testait `reserves`, tout ce qui n'était pas
    explicitement FERMÉ était ouvert : pas de politique, politique muette, futur
    appelant qui oublie de la passer. Or un domaine fictif sous TLD réel peut
    appartenir à quelqu'un exactement comme une IP routable, et cette
    question-là avait déjà été tranchée dans l'autre sens (RFC 2544, round 18).
    Traiter la même classe de risque de deux façons dans un même système,
    c'était l'incohérence.

    `tld_reels` reste atteignable — il faut le DÉCLARER, ce qui est le sens de
    l'ouverture dans ce projet."""
    assert tld(moteur.substitute_value("HOSTNAME", hote)) in RESERVED_TLDS
