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
def test_un_domaine_ordinaire_garde_l_arbitrage_de_l_operateur(moteur, hote):
    """Le pendant : pour un domaine qui n'était PAS réservé, le choix reste
    celui du réglage `domaines_fictifs`. Sans réglage, la plausibilité (D1)
    l'emporte — c'est le défaut documenté, pas une omission."""
    assert tld(moteur.substitute_value("HOSTNAME", hote)) not in RESERVED_TLDS
