"""Critère de sortie Phase 2 (plan §5) — test de propriété sur 10 000 valeurs :

  - injectivité   : aucune collision de substitut (par portée) ;
  - déterminisme  : deux exécutions (coffres neufs, même clé maître, même ordre)
                    produisent des sorties identiques octet pour octet ;
  - attributs     : environnement conservé, co-appartenance /24 conservée,
                    privé reste privé, interne reste interne, humain/service
                    distincts.

Valeurs 100 % SYNTHÉTIQUES.
"""
from __future__ import annotations

import ipaddress

import pytest

from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "a3" * 32  # clé de test fixe (synthétique)
SCOPE = "project:demo"

ENVS = ["prod", "staging", "dev"]
ORGS = [f"org{i:03d}" for i in range(300)]
WORDS = ["payments", "checkout", "ledger", "catalog", "search", "billing",
         "orders", "identity", "notify", "ingest"]


def make_engine(tmp_path, name="v1"):
    return SurrogateEngine(
        vault=Vault(tmp_path / f"{name}.db", master_key=MASTER), master_key=MASTER, scope_key=SCOPE
    )


def corpus() -> list[tuple[str, str]]:
    """(etype, valeur) — 10 000 valeurs synthétiques, ordre fixe."""
    vals: list[tuple[str, str]] = []
    for i in range(3000):  # hostnames avec env, 300 « orgs »
        org = ORGS[i % 300]
        w = WORDS[i % 10]
        env = ENVS[i % 3]
        vals.append(("HOSTNAME", f"{w}-{i:04d}-{env}.{org}.internal"))
    for i in range(3000):  # IPs privées réparties sur 100 /24
        vals.append(("IP_ADDRESS", f"10.{(i % 100) // 8}.{i % 100}.{(i % 250) + 1}"))
        if len([v for v in vals if v[0] == "IP_ADDRESS"]) >= 3000:
            break
    # complète exactement à 3000 IPs (l'expression au-dessus peut boucler court)
    n_ip = sum(1 for t, _ in vals if t == "IP_ADDRESS")
    for i in range(3000 - n_ip):
        vals.append(("IP_ADDRESS", f"172.16.{i % 200}.{(i % 250) + 1}"))
    for i in range(1000):  # emails humains
        vals.append(("EMAIL_ADDRESS", f"prenom{i:04d}.nom{i:04d}@{ORGS[i % 300]}.example"))
    for i in range(1000):  # emails de comptes de service
        vals.append(("EMAIL_ADDRESS", f"svc-{WORDS[i % 10]}-{i:04d}@{ORGS[i % 300]}.example"))
    for i in range(1000):  # dépôts org/nom
        vals.append(("URL", f"https://github.com/{ORGS[i % 300]}/{WORDS[i % 10]}-{i:04d}"))
    for i in range(1000):  # identifiants génériques avec env
        vals.append(("SERVICE_ACCOUNT", f"svc-{WORDS[i % 10]}{i:04d}-{ENVS[i % 3]}"))
    assert len(vals) == 10_000
    return vals + adversarial()


def adversarial() -> list[tuple[str, str]]:
    """Cas durs que le corpus régulier ne couvre pas.

    Un corpus généré par gabarits est trop propre : il ne prouve rien sur les
    formes qui cassent réellement un moteur de substitution.
    """
    vals: list[tuple[str, str]] = []
    for i in range(60):  # IPv6, y compris denses sur un même /64
        vals.append(("IP_ADDRESS", f"fd00:{i % 8:x}::{i:x}"))
    for i in range(60):  # IP publiques (classe privé/public à préserver)
        vals.append(("IP_ADDRESS", f"51.{i % 256}.{(i * 7) % 256}.{i % 254 + 1}"))
    for i in range(40):  # hôtes hors `.internal`
        vals.append(("HOSTNAME", f"edge{i:03d}.{ORGS[i]}.example.com"))
    for i in range(20):  # noms très courts, sans chiffre ni séparateur
        vals.append(("HOSTNAME", f"{chr(97 + i % 26)}{chr(97 + (i * 3) % 26)}"))
    for i in range(20):  # très longs
        vals.append(("HOSTNAME", ("x" * 60 + f"{i:02d}") + ".acme.internal"))
    for i in range(20):  # caractères spéciaux JSON dans un chemin
        vals.append(("FILE_PATH", f'/srv/"quote"/back\\slash/tab\tnl\n{i:02d}'))
    for i in range(20):  # Unicode et emoji
        vals.append(("HOSTNAME", f"café-{i:02d}.münchen.internal"))
    for i in range(20):  # préfixes stricts les uns des autres
        vals.append(("HOSTNAME", "node" + "0" * (i + 1) + ".acme.internal"))
    for i in range(20):  # UUID de versions différentes
        vals.append(("UUID", f"{i:08x}-1234-{(i % 5) + 1}234-a234-123456789012"))
    for i in range(20):  # MAC des trois notations
        h = f"{i:02x}"
        vals.append(("MAC_ADDRESS", f"{h}:bb:cc:dd:ee:ff"))
        vals.append(("MAC_ADDRESS", f"{h}bb.ccdd.eeff"))
    return vals


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    """Deux exécutions indépendantes (coffres neufs) sur le même corpus."""
    tmp = tmp_path_factory.mktemp("props")
    data = corpus()
    outs = []
    for name in ("run_a", "run_b"):
        eng = make_engine(tmp, name)
        outs.append([(t, v, eng.substitute_value(t, v)) for t, v in data])
    return outs


def test_injectivite_aucune_collision(runs):
    a = runs[0]
    reals = {(t, v) for t, v, _ in a}
    # deux réels distincts ne partagent jamais un substitut
    by_surrogate: dict[str, set[str]] = {}
    for _, v, s in a:
        by_surrogate.setdefault(s, set()).add(v)
    collisions = {s: vs for s, vs in by_surrogate.items() if len(vs) > 1}
    assert not collisions, f"collisions de substituts : {list(collisions.items())[:3]}"
    assert len(reals) == len({v for _, v, _ in a})


def test_determinisme_octet_pour_octet(runs):
    assert runs[0] == runs[1]


def test_attribut_environnement_conserve(runs):
    for t, v, s in runs[0]:
        for env in ENVS:
            if f"-{env}" in v or v.endswith(env):
                assert env in s, f"env {env!r} perdu : {v!r} → {s!r}"
                for other in ENVS:
                    if other != env and other not in v:
                        assert other not in s, f"env inventé {other!r} : {v!r} → {s!r}"


def test_attribut_co_appartenance_24(runs):
    # La co-appartenance se mesure sur /24 en IPv4 et sur /64 en IPv6 :
    # appliquer /24 à une adresse v6 regrouperait des réseaux sans rapport.
    net_map: dict[str, set[str]] = {}
    for t, v, s in runs[0]:
        if t != "IP_ADDRESS":
            continue
        prefixe = 24 if ipaddress.ip_address(v).version == 4 else 64
        real_net = str(ipaddress.ip_network(f"{v}/{prefixe}", strict=False))
        fake_net = str(ipaddress.ip_network(f"{s}/{prefixe}", strict=False))
        net_map.setdefault(real_net, set()).add(fake_net)
    # même /24 réel → un seul /24 fictif
    bad = {k: v for k, v in net_map.items() if len(v) > 1}
    assert not bad, f"/24 éclatés : {list(bad.items())[:3]}"
    # deux /24 réels distincts → /24 fictifs distincts
    all_fakes = [next(iter(v)) for v in net_map.values()]
    assert len(all_fakes) == len(set(all_fakes)), "fusion de /24 distincts"


def test_attribut_prive_reste_prive(runs):
    """L'attribut préservé est « INTERNE vs externe » (§3.4), pas `is_private`.

    Les deux ne coïncident pas : `ipaddress` range avec le RFC 1918 les plages
    de DOCUMENTATION et de BANC D'ESSAI, qui tiennent la place d'adresses
    routables — et c'est justement dans le banc d'essai que le moteur émet son
    espace public fictif, faute de pouvoir émettre chez un tiers. Ce test
    portait sur `is_private` et figeait donc l'ancienne confusion.
    """
    from anonproxy.surrogates.canonical import est_privee

    for t, v, s in runs[0]:
        if t != "IP_ADDRESS":
            continue
        assert est_privee(ipaddress.ip_address(v)) == est_privee(ipaddress.ip_address(s)), \
            f"classe interne/externe non conservée : {v} → {s}"


def test_attribut_interne_conserve(runs):
    for t, v, s in runs[0]:
        if t == "HOSTNAME" and v.endswith(".internal"):
            assert s.endswith(".internal"), f"suffixe interne perdu : {v} → {s}"


def test_attribut_humain_vs_service(runs):
    for t, v, s in runs[0]:
        if t != "EMAIL_ADDRESS":
            continue
        if v.startswith("svc-"):
            assert s.split("@")[0].startswith("svc-"), f"service devenu humain : {v} → {s}"
        else:
            assert not s.split("@")[0].startswith("svc-"), f"humain devenu service : {v} → {s}"


def test_reversibilite_via_coffre(runs, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("rev")
    eng = make_engine(tmp)
    pairs = [("HOSTNAME", "api-42-prod.org001.internal"),
             ("IP_ADDRESS", "10.1.2.3"),
             ("EMAIL_ADDRESS", "a.b@org001.example")]
    for t, v in pairs:
        s = eng.substitute_value(t, v)
        view = eng.surrogates_view()
        assert view.get(s) == v, f"substitut non réversible : {v} → {s}"
