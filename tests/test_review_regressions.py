"""Non-régressions issues de la revue adversariale (3 agents, effort max).

Chaque test correspond à une faille PROUVÉE par la revue puis corrigée. Ils
existent pour qu'aucune ne puisse revenir silencieusement.
Données synthétiques uniquement.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from anonproxy.surrogates.engine import SurrogateEngine  # noqa: E402
from anonproxy.surrogates.overlap import resolve_overlaps  # noqa: E402
from anonproxy.vault import Vault  # noqa: E402

MASTER = "ab" * 32


def engine(tmp_path, scope="project:rt") -> SurrogateEngine:
    return SurrogateEngine(vault=Vault(tmp_path / "v.db"), master_key=MASTER, scope_key=scope)


# --------------------------------------------------------------------------- #
# CRITIQUE 1 & 2 — un attribut partagé pouvait se substituer à LUI-MÊME
# --------------------------------------------------------------------------- #


def test_zone_ne_se_substitue_jamais_a_elle_meme(tmp_path):
    """Le lexique fini finissait par retomber sur la zone réelle, qui partait
    alors en clair (`web-01.lamna.internal` → `beacon-01.lamna.internal`)."""
    eng = engine(tmp_path)
    for zone in ("lamna.internal", "adventure.local", "fourth.local",
                 "northwind.internal", "contoso.internal", "trey.corp",
                 "litware.lan", "coho.intra"):
        real = f"web-01.{zone}"
        fake = eng.substitute_value("HOSTNAME", real)
        assert not fake.endswith(f".{zone}"), f"zone réelle conservée : {real} → {fake}"


def test_prefixe_24_ne_se_substitue_jamais_a_lui_meme(tmp_path):
    """Idem pour les sous-réseaux : `172.22.96.42` → `172.22.96.45` exposait
    le bloc RFC1918 réellement utilisé."""
    eng = engine(tmp_path)
    for i in range(60):
        real = f"172.{16 + i % 16}.{i * 3 % 256}.42"
        fake = eng.substitute_value("IP_ADDRESS", real)
        assert fake.rsplit(".", 1)[0] != real.rsplit(".", 1)[0], \
            f"/24 réel conservé : {real} → {fake}"


# --------------------------------------------------------------------------- #
# CRITIQUE 3 — spans invalides : duplication silencieuse de la valeur réelle
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("start,end", [
    (14, 6),      # inversé
    (6, 200),     # fin hors bornes
    (200, 300),   # entièrement hors bornes
    (-5, 3),      # début négatif
    (6, 6),       # vide
])
def test_span_invalide_refuse(tmp_path, start, end):
    eng = engine(tmp_path)
    text = "hello 10.0.0.1 world"
    with pytest.raises(ValueError):
        eng.transform(text, [{"type": "IP_ADDRESS", "start": start, "end": end,
                              "value": "10.0.0.1", "score": 0.9}])


# --------------------------------------------------------------------------- #
# MAJEUR 4 & 5 — une entité = UNE identité fictive
# --------------------------------------------------------------------------- #


def test_meme_hote_sous_plusieurs_types_une_seule_identite(tmp_path):
    eng = engine(tmp_path)
    subs = {eng.substitute_value(t, "db-01.acme.internal")
            for t in ("HOSTNAME", "FQDN", "CERT_CN", "HEX_HOSTNAME")}
    assert len(subs) == 1, f"{len(subs)} identités fictives pour un seul hôte : {subs}"


def test_casse_et_espaces_ne_creent_pas_de_doublons(tmp_path):
    eng = engine(tmp_path)
    subs = {eng.substitute_value("HOSTNAME", v) for v in (
        "db-01.acme.internal", "DB-01.acme.internal", "Db-01.Acme.Internal",
        "db-01.ACME.INTERNAL", "  db-01.acme.internal  ", "db-01.acme.internal.",
    )}
    assert len(subs) == 1, f"variantes d'écriture → {len(subs)} substituts : {subs}"


def test_ip_avec_espaces_parasites(tmp_path):
    eng = engine(tmp_path)
    subs = {eng.substitute_value("IP_ADDRESS", v) for v in ("10.0.0.1", "10.0.0.1 ", " 10.0.0.1")}
    assert len(subs) == 1


# --------------------------------------------------------------------------- #
# MAJEUR 6 — recouvrement partiel : la partie non couverte doit être traitée
# --------------------------------------------------------------------------- #


def test_recouvrement_partiel_ne_laisse_rien_en_clair(tmp_path):
    eng = engine(tmp_path)
    text = "http://sales.acme.com/user?login=alice@acme.com"
    spans = [
        {"type": "URL", "start": 0, "end": 40, "value": text[0:40], "score": 0.9},
        {"type": "EMAIL_ADDRESS", "start": 33, "end": 46, "value": text[33:46], "score": 0.99},
    ]
    out = eng.transform(text, spans)
    assert "acme.com" not in out, f"domaine réel en clair après arbitrage : {out!r}"


def test_fragments_non_couverts_conserves():
    spans = [
        {"type": "URL", "start": 0, "end": 40, "value": "x", "score": 0.9},
        {"type": "EMAIL_ADDRESS", "start": 33, "end": 46, "value": "y", "score": 0.99},
    ]
    kept = resolve_overlaps(spans)
    couvert = set()
    for s in kept:
        couvert |= set(range(s["start"], s["end"]))
    assert set(range(0, 46)) <= couvert, "une zone détectée n'est plus couverte"


# --------------------------------------------------------------------------- #
# MAJEUR 7 — le tag d'image porte souvent des identifiants sensibles
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tag", [
    "af12b3c4d5e6f7890000000000000000",     # SHA de commit
    "jean-dupont-poc",                       # login
    "feat/PROJ-1234-secret-migration",       # branche + ticket
    "v1.2.3-hotfix-CUSTOMER-nda-breach",     # nom de client
])
def test_tag_image_sensible_substitue(tmp_path, tag):
    eng = engine(tmp_path)
    out = eng.substitute_value("CONTAINER_IMAGE", f"registry.acme.io/backend/api:{tag}")
    assert tag.lower() not in out.lower(), f"tag sensible conservé : {out}"


@pytest.mark.parametrize("tag", ["1.27", "v4.2.1", "latest", "stable", "alpine"])
def test_tag_image_public_conserve(tmp_path, tag):
    eng = engine(tmp_path)
    out = eng.substitute_value("CONTAINER_IMAGE", f"registry.acme.io/backend/api:{tag}")
    assert out.endswith(f":{tag}"), f"version publique perdue : {out}"


# --------------------------------------------------------------------------- #
# Fuite E2E — le chemin d'une URL restait en clair
# --------------------------------------------------------------------------- #


def test_chemin_url_substitue(tmp_path):
    """Observé en session réelle : `registry.acmecorp.io/payments/api:4.2.1`
    devenait `tundra.trey.net/payments/api:4.2.1` — hôte masqué, chemin nu."""
    eng = engine(tmp_path)
    out = eng.substitute_value("URL", "https://registry.acmecorp.io/payments/api")
    assert "payments" not in out and "acmecorp" not in out, out
    assert out.startswith("https://") and out.count("/") == 4


def test_valeurs_de_query_substituees(tmp_path):
    eng = engine(tmp_path)
    out = eng.substitute_value("URL", "https://portail.acme.internal/x?tenant=acmecorp&id=42")
    assert "acmecorp" not in out
    assert "tenant=" in out and "id=" in out, f"noms de paramètres perdus : {out}"


# --------------------------------------------------------------------------- #
# MAJEUR 8 — types internes non forgeables depuis un span
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("etype", ["_SUBNET_V4", "_SUBNET_V6", "_ZONE", "_REPO_ORG", "_REGISTRY"])
def test_type_interne_refuse(tmp_path, etype):
    eng = engine(tmp_path)
    with pytest.raises(ValueError):
        eng.substitute_value(etype, "10.0.0.0")


def test_empoisonnement_ne_casse_pas_les_ip(tmp_path):
    """Le scénario complet de la revue : span forgé puis IP réelle du réseau."""
    eng = engine(tmp_path)
    with pytest.raises(ValueError):
        eng.substitute_value("_SUBNET_V4", "10.0.0.0")
    assert eng.substitute_value("IP_ADDRESS", "10.0.0.42")  # ne doit pas planter


# --------------------------------------------------------------------------- #
# MINEUR 10 — la racine « / » faisait échouer la substitution
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", ["/", "//", "///"])
def test_racine_ne_plante_pas(tmp_path, path):
    assert engine(tmp_path).substitute_value("FILE_PATH", path) == path
