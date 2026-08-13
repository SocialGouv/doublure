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


def test_aucun_domaine_fictif_ne_porte_un_tld_reel_par_defaut(moteur):
    """L'arbitrage est RENDU, et il ferme (2026-08-12).

    Ce test MESURAIT un résidu : 40 hôtes externes sur 40 combinaient un mot de
    société fictive et un TLD RÉEL, donc `alpine-relecloud.net` pouvait
    appartenir à quelqu'un. Le vérifier demanderait une requête DNS, donc une
    sortie réseau que D9 interdit — on ne pouvait ni l'affirmer ni l'exclure.

    Même famille que le défaut « substitut routable », qui, lui, avait été
    tranché en faveur de l'espace réservé (RFC 2544) sans que ce soit
    négociable. Traiter la même classe de risque de deux façons dans un même
    système était l'incohérence ; le prix payé est la plausibilité, et son
    échec est VISIBLE — celui de l'autre branche ne l'est pas.
    """
    reserves = {"example", "invalid", "test", "localhost"}
    externes = [moteur.substitute_value("HOSTNAME", f"www-{i:02d}.acmecorp-externe.fr")
                for i in range(40)]
    fuyants = [h for h in externes
               if h.rsplit(".", 1)[-1].lower() not in reserves]
    assert not fuyants, (
        f"{len(fuyants)}/{len(externes)} hôtes fictifs portent un TLD réel, "
        f"donc peuvent désigner la machine de quelqu'un : {fuyants[:3]}")
    # Les hôtes INTERNES, eux, restent sur un suffixe non résolvable.
    internes = [moteur.substitute_value("HOSTNAME", f"db-{i:02d}-prod.acmecorp.internal")
                for i in range(40)]
    assert all(h.endswith(".internal") for h in internes), internes[:3]


def test_residu_le_tld_reel_reste_atteignable_mais_se_declare(tmp_path):
    """Le résidu ne disparaît pas : il change de statut.

    Sous `domaines_fictifs=tld_reels`, les hôtes externes retrouvent un TLD
    réel — c'est le but du réglage, et l'opérateur qui l'écrit accepte
    l'exposition. Ce que le défaut ne fait plus, c'est la choisir pour lui."""
    from anonproxy.modes import DOMAINES_TLD_REELS
    from anonproxy.policy import Policy
    from anonproxy.surrogates.lexicon import EXTERNAL_TLDS

    politique = Policy(racine=tmp_path / "policy", master_key=MASTER,
                       scope_key=SCOPE)
    politique.definir_reglage("projet", "domaines_fictifs", DOMAINES_TLD_REELS)
    ouvert = SurrogateEngine(vault=Vault(tmp_path / "o.db", master_key=MASTER),
                             master_key=MASTER, scope_key=SCOPE,
                             policy=politique)
    externes = [ouvert.substitute_value("HOSTNAME", f"www-{i:02d}.acmecorp-externe.fr")
                for i in range(40)]
    sur_tld_reel = [h for h in externes
                    if h.rsplit(".", 1)[-1].lower() in EXTERNAL_TLDS]
    print(f"\nRÉSIDU SOUS OUVERTURE DÉCLARÉE : {len(sur_tld_reel)}/{len(externes)} "
          f"hôtes portent un TLD réel ({', '.join(EXTERNAL_TLDS)}) ; leur "
          "disponibilité n'est pas vérifiable sans requête DNS.")
    assert sur_tld_reel, "le réglage doit rester effectif"


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


#: Les dates PARTIELLES — un rapport d'incident en est fait. Aucune n'était
#: décalée : elles tombaient au repli générique et sortaient en MOT.
DATES_PARTIELLES = [
    ("August 2026", "mois-année anglophone"),
    ("février 2026", "mois-année francophone"),
    ("Feb. 2026", "mois-année abrégé"),
    ("2026-08", "année-mois ISO"),
    ("Feb 28", "mois-jour, sans année"),
    ("28 février", "jour-mois, sans année"),
    ("Q3 2024", "trimestre-année"),
]


@pytest.mark.parametrize("valeur,forme", DATES_PARTIELLES,
                         ids=[f for _, f in DATES_PARTIELLES])
def test_une_date_PARTIELLE_reste_une_date(moteur, valeur, forme):
    """L'invariant de nature, sur le type qu'il n'exerçait PAS.

    Le corpus de `test_le_substitut_a_la_meme_nature_que_le_reel` ne porte
    aucune DATE, et il ne le pourrait pas : les natures qu'il énumère sont
    `{ip, cidr, host, email, repo, image, generic}` — une date et un mot y sont
    tous deux `generic`. L'invariant du tour 18 annonçait qu'il couvrait « les
    suivantes » ; sur les dates il ne peut rien dire. Il est donc énoncé ici, où
    il est vérifiable : ce qui se lit comme une date doit se relire comme une
    date, et de la MÊME forme.

    Mesuré en session réelle : `'Feb 28' → 'orchard-larch'`,
    `'August 2026' → 'gateway-sedge'`. Le modèle reçoit un nom d'hôte là où le
    document annonce une date, et cesse de pouvoir répondre « quand ».
    """
    from anonproxy.surrogates import dates

    lu = dates.parse(valeur)
    assert lu is not None, f"{valeur!r} n'est pas lue comme une date"
    substitut = moteur.substitute_value("DATE", valeur)
    assert substitut != valeur, "l'identité n'est pas une substitution"
    relu = dates.parse(substitut)
    assert relu is not None, (
        f"nature perdue : {valeur!r} ({forme}) → {substitut!r}, qui ne se relit "
        "pas comme une date")


@pytest.mark.parametrize("valeur,forme", DATES_PARTIELLES,
                         ids=[f for _, f in DATES_PARTIELLES])
def test_une_date_PARTIELLE_ne_gagne_ni_ne_perd_de_champ(moteur, valeur, forme):
    """L'AUTRE moitié : la même forme, pas seulement « une date ».

    Rendre `12 mars 2031` pour `August 2026` serait une date — et une INVENTION :
    le document ne dit pas le jour, et le substitut le ferait croire. La forme se
    mesure par ce que la valeur porte de chiffres et de mots.
    """
    import re

    substitut = moteur.substitute_value("DATE", valeur)
    chiffres = lambda v: [len(g) for g in re.findall(r"\d+", v)]  # noqa: E731
    assert chiffres(substitut) == chiffres(valeur), (
        f"{valeur!r} → {substitut!r} : la forme a changé de champs")


@pytest.mark.parametrize("valeur,interdit", [
    ("2020-02-30", "2020"),   # la FORME d'une date, sans en être une
    ("hiver 1998", "1998"),   # une SAISON : aucune date ne s'en déduit
])
def test_une_date_qui_tombe_au_generique_n_emporte_pas_son_annee(moteur, valeur,
                                                                 interdit):
    """Le repli générique recopie le premier groupe de CHIFFRES de la valeur.

    C'est un INDEX gardé pour la plausibilité (`srv-42` → `glacier-vault42`).
    Pour une DATE, ces chiffres sont le CONTENU : l'année réelle repartait dans
    le substitut, sans entrée au coffre pour elle, sans substitut non résolu,
    rien à compter.
    """
    from anonproxy.surrogates import dates
    assert dates.shift(valeur, 654) is None, \
        "cette valeur se décale, donc elle ne passe PAS par le repli : le cas " \
        "ne prouverait rien"
    substitut = moteur.substitute_value("DATE", valeur)
    assert interdit not in substitut, substitut


def test_une_date_au_bord_de_la_plage_ne_repart_pas_en_clair(moteur):
    """`9999-12-31` — la date « sans fin » des contrats — débordait à
    l'addition et repartait VERBATIM dans le substitut. Elle tourne désormais
    dans la plage, donc elle reste une date ET ne fuit plus."""
    substitut = moteur.substitute_value("DATE", "expire le 9999-12-31")
    assert "9999" not in substitut and "12-31" not in substitut, substitut


@pytest.mark.parametrize("etype,valeur,interdit", [
    ("USERNAME", "jdoe1985", "1985"),          # une année de naissance
    ("CPF", "123.456.789-01", "123"),
    ("K8S_NAMESPACE", "prod-2024-billing", "2024"),
    ("SERVICE_ACCOUNT", "billing-2024-042", "2024"),
    # Et l'autre MOITIÉ, celle que la première version du test avait manquée :
    # une valeur qui COMMENCE par un préfixe d'infrastructure et porte quand
    # même du contenu numérique. Exiger le préfixe puis chercher le premier
    # nombre n'importe où reproduisait la fuite exactement.
    ("SERVICE_ACCOUNT", "svc-1985-jdoe", "1985"),
    ("SERVICE_ACCOUNT", "svc-jdoe1985", "1985"),
    ("SERVICE_ACCOUNT", "ns-19850201-jdoe", "198502"),
    ("K8S_NAMESPACE", "team-2024-billing", "2024"),
    ("K8S_NAMESPACE", "app-tenant-42-us", "42"),
])
def test_le_repli_ne_recopie_pas_les_chiffres_qui_sont_du_CONTENU(
        moteur, etype, valeur, interdit):
    """La correction précédente écartait la seule DATE : une liste NOIRE, donc
    fausse par construction.

    Tous les types sans branche dédiée tombent dans ce repli, et pour la
    plupart les chiffres sont le CONTENU, pas un index : `jdoe1985` gardait une
    année de naissance, un CPF ses trois premiers chiffres — l'équivalent de
    l'État de naissance dans un SSN. La liste n'aurait jamais fini de
    s'allonger ; c'est la condition qui devait s'inverser."""
    assert interdit not in moteur.substitute_value(etype, valeur)


def test_le_repli_garde_l_index_quand_un_prefixe_en_fait_un_index(moteur):
    """L'AUTRE MOITIÉ : là où un préfixe d'infrastructure annonce un index, il
    est gardé — sinon la correction aurait échangé une fuite contre une perte
    de plausibilité (D1).

    Le test précédent prétendait couvrir ça avec `srv-42.acme.internal`, qui
    passe en réalité par le générateur d'hôtes : il ne traversait pas ce
    repli."""
    for valeur, index in (("svc-42", "42"), ("svc-100", "100"),
                          ("svc-42-payment", "42"), ("bot-12_worker", "12")):
        assert index in moteur.substitute_value("SERVICE_ACCOUNT", valeur), valeur
