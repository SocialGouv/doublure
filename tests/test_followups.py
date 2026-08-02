"""Suites de la revue : robustesse, plausibilité, déterminisme.

Chaque test correspond à un point resté ouvert après le premier passage de
correctifs. Données synthétiques uniquement.
"""
from __future__ import annotations

import ipaddress
import re
import uuid

import pytest

from conftest import RecordingDetector

from anonproxy.pipeline import Pseudonymizer
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "cd" * 32


def engine(tmp_path, name="v", scope="project:fu") -> SurrogateEngine:
    return SurrogateEngine(vault=Vault(tmp_path / f"{name}.db", master_key=MASTER), master_key=MASTER, scope_key=scope)


# --------------------------------------------------------------------------- #
# Déterminisme indépendant de l'ordre d'insertion
# --------------------------------------------------------------------------- #


#: Part de substituts qui peuvent légitimement dépendre de l'ordre : ceux dont
#: le tirage entre en collision avec un autre dans la MÊME zone. Le premier
#: arrivé garde le nom, le second escalade — et cette escalade ne peut pas être
#: annulée après coup, un substitut déjà envoyé ne se reprend pas.
#: Mesuré à ~4 % sur un cas défavorable (50 hôtes sans chiffre, zone unique) ;
#: c'était 40 % avant l'élargissement de l'espace de tirage.
TOLERANCE_ORDRE = 0.05


def test_ordre_d_insertion_effet_borne(tmp_path):
    """Deux coffres NEUFS recevant les mêmes valeurs dans des ordres opposés
    produisent des substituts identiques, aux collisions de tirage près.

    Portée réelle du problème : un projet n'a qu'UN coffre, créé une fois — la
    divergence ne se manifeste donc pas entre deux sessions successives. Elle
    compte pour la reproductibilité d'une reconstruction de coffre. Le test
    garde la borne pour attraper une régression vers l'ancien comportement.
    """
    # Noms SANS chiffre : l'index numérique élargit l'espace et masquerait le
    # problème. C'est le cas que la revue a exhibé (`b.internal`, `k.internal`).
    values = [f"{c}{d}.internal" for c in "abcdefghij" for d in "klmno"]
    a = engine(tmp_path, "ordre-a")
    direct = {v: a.substitute_value("HOSTNAME", v) for v in values}

    b = engine(tmp_path, "ordre-b")
    inverse = {v: b.substitute_value("HOSTNAME", v) for v in reversed(values)}

    divergents = {v: (direct[v], inverse[v]) for v in values if direct[v] != inverse[v]}
    taux = len(divergents) / len(values)
    assert taux <= TOLERANCE_ORDRE, (
        f"{len(divergents)}/{len(values)} substituts dépendent de l'ordre "
        f"({taux:.0%} > {TOLERANCE_ORDRE:.0%}) : {list(divergents.items())[:3]}"
    )
    # ce qui reste vrai sans réserve : aucune collision, quel que soit l'ordre
    assert len(set(direct.values())) == len(values)
    assert len(set(inverse.values())) == len(values)


def test_determinisme_entre_coffres_neufs(tmp_path):
    """Même corpus, deux coffres neufs, même ordre : sortie identique."""
    values = [f"node-{i:03d}-prod.acme.internal" for i in range(50)]
    a = engine(tmp_path, "det-a")
    b = engine(tmp_path, "det-b")
    assert [a.substitute_value("HOSTNAME", v) for v in values] == \
           [b.substitute_value("HOSTNAME", v) for v in values]


# --------------------------------------------------------------------------- #
# Plausibilité (D1) : un substitut mal formé déclenche l'hallucination
# --------------------------------------------------------------------------- #


def test_ip_substituee_toujours_valide(tmp_path):
    eng = engine(tmp_path)
    for i in range(120):
        real = f"10.{i % 256}.{(i * 7) % 256}.{(i * 13) % 254 + 1}"
        ipaddress.ip_address(eng.substitute_value("IP_ADDRESS", real))


def test_ipv6_valide_et_prefixe_stable(tmp_path):
    eng = engine(tmp_path)
    subs = [eng.substitute_value("IP_ADDRESS", f"fd00:1234:5678:9abc::{i:x}") for i in range(1, 40)]
    for s in subs:
        assert ipaddress.ip_address(s).version == 6
    # même /64 réel → même /64 fictif, et assez d'espace d'hôte pour 40 machines
    prefixes = {str(ipaddress.ip_network(f"{s}/64", strict=False)) for s in subs}
    assert len(prefixes) == 1, f"/64 éclaté : {prefixes}"
    assert len(set(subs)) == len(subs), "collision d'hôtes IPv6"


def test_uuid_version_et_variante_preservees(tmp_path):
    eng = engine(tmp_path)
    for real in ("12345678-1234-1234-8234-123456789012",   # v1
                 "12345678-1234-4234-a234-123456789012",   # v4
                 "12345678-1234-5234-9234-123456789012"):  # v5
        fake = eng.substitute_value("UUID", real)
        assert uuid.UUID(fake)
        assert fake[14] == real[14], f"version changée : {real} → {fake}"
        assert fake[19] == real[19], f"variante changée : {real} → {fake}"


def test_mac_format_cisco_preserve(tmp_path):
    eng = engine(tmp_path)
    assert re.fullmatch(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}",
                        eng.substitute_value("MAC_ADDRESS", "aabb.ccdd.eeff"))
    assert re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}",
                        eng.substitute_value("MAC_ADDRESS", "aa:bb:cc:dd:ee:ff"))
    assert re.fullmatch(r"([0-9a-f]{2}-){5}[0-9a-f]{2}",
                        eng.substitute_value("MAC_ADDRESS", "aa-bb-cc-dd-ee-ff"))


def test_prefixe_d_algorithme_de_hash_conserve(tmp_path):
    eng = engine(tmp_path)
    real = "sha256:" + "ab" * 32
    fake = eng.substitute_value("HASH", real)
    assert fake.startswith("sha256:"), f"algorithme perdu : {fake}"
    assert len(fake) == len(real) and fake != real


def test_person_conserve_le_nombre_de_mots(tmp_path):
    eng = engine(tmp_path)
    for real in ("Alice", "Alice Dupont", "Marie-Anne De La Fontaine", "van der Meer"):
        fake = eng.substitute_value("PERSON", real)
        assert len(fake.split()) == len(real.split()), f"{real!r} → {fake!r}"


def test_url_ipv6_litteral(tmp_path):
    eng = engine(tmp_path)
    fake = eng.substitute_value("URL", "https://[fd00:1234:5678:9abc::1]:8443/admin")
    m = re.fullmatch(r"https://\[([0-9a-f:]+)\]:8443/(\S+)", fake)
    assert m, f"forme cassée : {fake}"
    assert ipaddress.ip_address(m.group(1)).version == 6
    assert "admin" not in fake


# --------------------------------------------------------------------------- #
# Unicode : NFC unifie, homoglyphes séparent
# --------------------------------------------------------------------------- #


def test_nfc_et_nfd_meme_entite(tmp_path):
    eng = engine(tmp_path)
    compose = "café-prod.acme.internal"        # é précomposé
    decompose = "café-prod.acme.internal"     # e + accent combinant
    assert eng.substitute_value("HOSTNAME", compose) == \
           eng.substitute_value("HOSTNAME", decompose)


def test_homoglyphes_restent_distincts(tmp_path):
    eng = engine(tmp_path)
    latin = eng.substitute_value("HOSTNAME", "db-01.acme.internal")
    cyrillique = eng.substitute_value("HOSTNAME", "db-01.аcme.internal")
    assert latin != cyrillique


# --------------------------------------------------------------------------- #
# Cache porté
# --------------------------------------------------------------------------- #


class _Detector:
    def detect(self, text, *, strategy=None):
        idx = text.find("db-01.acme.internal")
        return [] if idx < 0 else [{"type": "HOSTNAME", "start": idx, "end": idx + 19,
                                    "value": "db-01.acme.internal", "score": 0.9}]


def test_cache_isole_les_portees(tmp_path):
    """Un Pseudonymizer réutilisé entre deux portées ne doit pas servir le
    résultat de la première à la seconde."""
    vault = Vault(tmp_path / "v.db", master_key=MASTER)
    a = SurrogateEngine(vault=vault, master_key=MASTER, scope_key="project:a")
    b = SurrogateEngine(vault=vault, master_key=MASTER, scope_key="project:b")

    p = Pseudonymizer(_Detector(), a)
    out_a = p.to_surrogate("hôte db-01.acme.internal")
    p.engine = b
    out_b = p.to_surrogate("hôte db-01.acme.internal")
    assert out_a != out_b, "le cache a servi le substitut d'une autre portée"


def test_valeurs_courtes_analysees(tmp_path):
    """Aucun seuil de longueur : `db01` doit passer par le détecteur."""
    espion = RecordingDetector()
    p = Pseudonymizer(espion, engine(tmp_path))
    p.to_surrogate("db01")
    p.to_surrogate("jdoe")
    assert espion.seen == ["db01", "jdoe"]


def test_texte_sans_alphanumerique_ignore(tmp_path):
    espion = RecordingDetector()
    p = Pseudonymizer(espion, engine(tmp_path))
    for texte in ("", "   ", "\n\t", "--- ***"):
        assert p.to_surrogate(texte) == texte
    assert espion.seen == [], "un texte sans caractère alphanumérique a été analysé"
