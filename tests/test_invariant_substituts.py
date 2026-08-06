"""L'invariant unique dont les trois défauts du 2026-08-06 étaient des cas.

    Un substitut doit être indiscernable EN NATURE de ce qu'il remplace,
    et ne jamais désigner une entité du MONDE RÉEL.

Les trois défauts trouvés en session réelle en sont des violations :

  - `10.1.2.0/24` rendu sous un MOT           → nature perdue ;
  - une passerelle publique adressée en 10.x  → nature (interne/externe) ;
  - un substitut dans `198.51.32.0/24`        → machine d'un tiers.

Trois tests ponctuels auraient figé trois cas. Celui-ci ferme la CLASSE, et
c'est ce qui compte : les trois venaient d'un invariant jamais énoncé, pas
d'un oubli d'implémentation.

La formulation générique tient en une ligne : la forme canonique du substitut
doit avoir le même `kind` que celle du réel. C'est le moteur lui-même qui
définit ce qu'est « la nature d'une valeur » — on le réutilise plutôt que d'en
réécrire une seconde définition qui divergerait.

Ce qui n'est PAS prouvable localement (« ce domaine appartient-il à
quelqu'un ? » demanderait une requête DNS, donc une sortie réseau que D9
interdit) n'est pas affirmé : c'est COMPTÉ, et le compte est imprimé. Un
résidu assumé ne doit jamais être silencieux.
"""
from __future__ import annotations

import ipaddress

import pytest

from anonproxy.surrogates.canonical import canonicalize, est_privee
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "d4" * 32
SCOPE = "project:invariant"


@pytest.fixture(scope="module")
def moteur(tmp_path_factory):
    chemin = tmp_path_factory.mktemp("invariant") / "coffre.db"
    return SurrogateEngine(vault=Vault(chemin, master_key=MASTER),
                           master_key=MASTER, scope_key=SCOPE)


def corpus() -> list[tuple[str, str]]:
    """Un représentant de chaque NATURE que le moteur sait produire."""
    vals: list[tuple[str, str]] = []
    for i in range(40):
        vals += [
            ("HOSTNAME", f"db-{i:02d}-prod.acmecorp.internal"),
            ("HOSTNAME", f"www-{i:02d}.acmecorp-externe.fr"),
            ("IP_ADDRESS", f"10.{i % 250}.1.{i % 250 + 1}"),
            ("IP_ADDRESS", f"172.16.{i % 250}.{i % 250 + 1}"),
            ("IP_ADDRESS", f"51.{i % 250}.{(i * 7) % 250}.{i % 250 + 1}"),
            ("IP_ADDRESS", f"198.51.100.{i % 250 + 1}"),
            ("IP_ADDRESS", f"10.{i % 250}.1.0/24"),
            ("IP_ADDRESS", f"51.{i % 250}.{(i * 7) % 250}.0/24"),
            ("IP_ADDRESS", f"fd00:{i % 8:x}::{i:x}"),
            ("IP_ADDRESS", f"2001:db8:{i:x}::{i:x}"),
            ("IP_ADDRESS", f"fd00:{i % 8:x}::/64"),
            ("EMAIL_ADDRESS", f"prenom{i:02d}.nom{i:02d}@acmecorp.example"),
            ("EMAIL_ADDRESS", f"svc-agent-{i:02d}@acmecorp.example"),
            ("URL", f"https://github.com/acmecorp/service-{i:02d}"),
            ("URL", f"https://interne-{i:02d}.acmecorp.internal/tableau"),
            ("CONTAINER_IMAGE", f"registry.acmecorp.io/equipe/api-{i:02d}:4.2.1"),
            ("SERVICE_ACCOUNT", f"svc-paiement-{i:02d}-prod"),
        ]
    return vals


CAS = corpus()


# --------------------------------------------------------------------------- #
# 1. La NATURE est conservée
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("etype,reel", CAS, ids=[f"{t}:{v}" for t, v in CAS])
def test_le_substitut_a_la_meme_nature_que_le_reel(moteur, etype, reel):
    faux = moteur.substitute_value(etype, reel)
    assert faux != reel, "l'identité n'est pas une substitution"
    attendu = canonicalize(etype, reel).kind
    obtenu = canonicalize(etype, faux).kind
    assert obtenu == attendu, (
        f"nature perdue : {reel!r} ({attendu}) → {faux!r} ({obtenu})")


# --------------------------------------------------------------------------- #
# 2. Les ATTRIBUTS déclarés préservés le sont (§3.4)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("etype,reel", [c for c in CAS if c[0] == "IP_ADDRESS"],
                         ids=[v for t, v in CAS if t == "IP_ADDRESS"])
def test_interne_ou_externe_survit(moteur, etype, reel):
    faux = moteur.substitute_value(etype, reel)
    avant = ipaddress.ip_network(reel, strict=False)
    apres = ipaddress.ip_network(faux, strict=False)
    assert est_privee(avant) == est_privee(apres), (reel, faux)
    assert avant.version == apres.version, (reel, faux)
    assert avant.prefixlen == apres.prefixlen, (reel, faux)


# --------------------------------------------------------------------------- #
# 3. Aucun substitut ne désigne une entité du MONDE RÉEL
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("etype,reel", [c for c in CAS if c[0] == "IP_ADDRESS"],
                         ids=[v for t, v in CAS if t == "IP_ADDRESS"])
def test_aucun_substitut_n_est_routable(moteur, etype, reel):
    """Si le modèle propose une commande visant un substitut, elle doit
    n'atteindre personne. C'était le pire des trois défauts."""
    faux = moteur.substitute_value(etype, reel)
    reseau = ipaddress.ip_network(faux, strict=False)
    assert not reseau.is_global, f"{reel} → {faux} est routable"


def test_residu_les_domaines_fictifs_ne_sont_pas_prouvablement_libres(moteur):
    """RÉSIDU MESURÉ, pas affirmé — et volontairement bruyant.

    Un nom d'hôte externe fictif combine un mot de société fictive et un TLD
    RÉEL (`com`, `net`, `io`, `org`, `co`, `dev`) : `alpine-relecloud.net`
    peut très bien appartenir à quelqu'un. Le vérifier demanderait une requête
    DNS, donc une sortie réseau que D9 interdit — donc on ne l'affirme pas.

    Même famille que le défaut « substitut routable », surface plus large.
    L'alternative (`.example`, `.invalid`, `.test`, RFC 2606) est prouvablement
    à personne mais se lit comme fictive, ce qui abîme D1. Arbitrage de jo,
    pas d'implémentation.
    """
    from anonproxy.surrogates.lexicon import EXTERNAL_TLDS

    externes = [moteur.substitute_value("HOSTNAME", f"www-{i:02d}.acmecorp-externe.fr")
                for i in range(40)]
    reserves = {"example", "invalid", "test", "localhost"}
    sur_tld_reel = [h for h in externes
                    if h.rsplit(".", 1)[-1].lower() not in reserves]
    print(f"\nRÉSIDU : {len(sur_tld_reel)}/{len(externes)} hôtes externes "
          f"fictifs portent un TLD RÉEL ({', '.join(EXTERNAL_TLDS)}).")
    print("        Leur disponibilité n'est pas vérifiable sans requête DNS.")
    # Les hôtes INTERNES, eux, restent sur un suffixe non résolvable.
    internes = [moteur.substitute_value("HOSTNAME", f"db-{i:02d}-prod.acmecorp.internal")
                for i in range(40)]
    assert all(h.endswith(".internal") for h in internes), internes[:3]


# --------------------------------------------------------------------------- #
# 4. Le résidu ne doit pas grandir en silence
# --------------------------------------------------------------------------- #
def test_les_natures_couvertes_sont_enumerees(moteur):
    """Un `kind` nouveau doit passer par ici avant d'exister.

    Sans cette liste, ajouter une nature au moteur la ferait échapper à
    l'invariant sans que rien ne le signale.
    """
    vues = {canonicalize(t, v).kind for t, v in CAS}
    assert vues == {"ip", "cidr", "host", "email", "repo", "image", "generic"}, vues
