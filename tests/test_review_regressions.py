"""Non-régressions issues de la revue adversariale (3 agents, effort max).

Chaque test correspond à une faille PROUVÉE par la revue puis corrigée. Ils
existent pour qu'aucune ne puisse revenir silencieusement.
Données synthétiques uniquement.
"""
from __future__ import annotations


import pytest


from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.surrogates.overlap import resolve_overlaps
from anonproxy.vault import Vault

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
    # URL inclus : un hôte nu détecté comme URL recevait sa propre identité.
    subs = {eng.substitute_value(t, "db-01.acme.internal")
            for t in ("HOSTNAME", "FQDN", "CERT_CN", "HEX_HOSTNAME", "URL")}
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
    # Assertion élargie : ne chercher que « acme.com » laissait passer un
    # `_fake_query` neutralisé, qui pourtant recopiait la query et `alice`.
    for fragment in ("acme.com", "acme", "sales", "alice", "login=alice"):
        assert fragment not in out, f"fuite : {fragment!r} dans {out!r}"


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
# Revue finale — l'autorité et le fragment d'une URL fuyaient
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("url,interdits", [
    # userinfo : `partition(":")` prenait `user` pour l'hôte et recopiait
    # `:motdepasse@hôte.réel` en guise de « port ».
    ("https://alice.dupont:MyR3alPass@backend.acme.internal:5432/health",
     ["alice.dupont", "MyR3alPass", "acme.internal"]),
    ("postgres://user:s3cret@internal-db.acme.corp/mydb", ["s3cret", "acme.corp"]),
    ("https://svc-deploy@registry.acme.internal/v2/", ["svc-deploy", "acme.internal"]),
    # fragment : traité comme une paire `nom=valeur`, donc jamais substitué
    ("https://portal.acmecorp.com/#tenant-acmecorp-nda-project",
     ["acmecorp", "nda-project"]),
    ("https://wiki.acme.internal/page#SECRET-CUSTOMER", ["SECRET-CUSTOMER", "acme"]),
    ("https://api.acme.internal/x?a=b#alice-dupont-migration", ["alice-dupont"]),
    # paramètre sans valeur : la donnée EST le nom
    ("https://api.acme.internal/x?acmecorp-tenant", ["acmecorp"]),
    # IPv6 sans crochets : tout ce qui suivait le premier « : » était recopié
    ("https://fd00:1234:5678::42:8080/health", ["fd00:1234", "::42"]),
])
def test_url_aucune_partie_reelle_ne_survit(tmp_path, url, interdits):
    out = engine(tmp_path).substitute_value("URL", url)
    fuites = [m for m in interdits if m in out]
    assert not fuites, f"{fuites} survivent dans {out!r}"


def test_hote_d_url_enregistre_dans_le_coffre(tmp_path):
    """L'hôte d'une URL était généré sans passer par le coffre : son substitut
    restait libre, et un AUTRE hôte réel pouvait ensuite l'obtenir — la
    restauration désignait alors la mauvaise machine (D6)."""
    eng = engine(tmp_path)
    url = eng.substitute_value("URL", "http://aabc.acmecorp.internal/api")
    hote_fictif = url.split("//", 1)[1].split("/", 1)[0]
    vue = eng.surrogates_view()
    assert vue.get(hote_fictif) == "aabc.acmecorp.internal", \
        "l'hôte de l'URL n'est pas enregistré : son substitut est réattribuable"
    # aucun autre hôte réel ne peut désormais obtenir ce substitut
    autres = {eng.substitute_value("HOSTNAME", f"aa{c}.acmecorp.internal") for c in "bcdefghij"}
    assert hote_fictif not in autres


@pytest.mark.parametrize("valeur", [
    "...policy.consolidated.dev",   # points de troncature d'un span détecté
    "api.acme.internal",
    "acme.internal.",               # point final significatif pour le résolveur
    "sous.domaine.tres.long.acme.internal",
])
def test_url_hote_nu_partage_l_identite_de_l_hote(tmp_path, valeur):
    """Une URL réduite à un hôte EST cet hôte. La traiter à part créait une
    seconde entrée de coffre pour un substitut déjà pris : conflit d'unicité
    insoluble par régénération, donc 503 en pleine session."""
    eng = engine(tmp_path)
    assert eng.substitute_value("URL", valeur) == eng.substitute_value("HOSTNAME", valeur)


def test_allowlist_partagee_avec_les_sous_parties(tmp_path):
    """« Ce token est public » ne doit être maintenu qu'à un endroit.

    Le détecteur applique l'allowlist aux entités ENTIÈRES ; les composants
    d'une valeur composite (tag d'image, segment d'URL) ne lui sont jamais
    soumis isolément. Le moteur consulte donc la même liste.
    """
    from anonproxy.surrogates.engine import SurrogateEngine

    eng = SurrogateEngine(vault=Vault(tmp_path / "v.db"), master_key=MASTER,
                          scope_key="project:rt",
                          is_public=lambda v: v in {"python3.12-slim", "healthz"})
    image = eng.substitute_value("CONTAINER_IMAGE", "registry.acme.io/app:python3.12-slim")
    assert image.endswith(":python3.12-slim"), f"tag public substitué : {image}"
    url = eng.substitute_value("URL", "https://api.acme.internal/healthz")
    assert url.endswith("/healthz"), f"segment public substitué : {url}"
    assert "acme" not in url


def test_url_avec_et_sans_slash_final_identiques(tmp_path):
    """`https://hôte` et `https://hôte/` sont la même ressource : deux
    enregistrements pour un même substitut bloquaient la substitution."""
    eng = engine(tmp_path)
    assert eng.substitute_value("URL", "https://portail.acme.internal") == \
           eng.substitute_value("URL", "https://portail.acme.internal/")


def test_identifiants_d_url_jamais_stockes(tmp_path):
    """D4 — une URL de dépôt porteuse d'un jeton mettait le jeton dans la
    colonne `real` du coffre : il redevenait restaurable."""
    eng = engine(tmp_path)
    jeton = "ghp_syntheticDemoToken1234567890abcd"
    eng.substitute_value("URL", f"https://oauth2:{jeton}@github.com/acmecorp/payments")
    stocke = "\n".join(f"{k} {v}" for k, v in eng.surrogates_view().items())
    assert jeton not in stocke, "le jeton est dans le coffre, donc restaurable"
    assert "oauth2" not in stocke


def test_substitut_ne_reprend_pas_un_mot_du_reel(tmp_path):
    """Un mot du lexique peut coïncider avec un mot de la valeur réelle : le
    substitut garderait un morceau reconnaissable de l'original (D1)."""
    eng = engine(tmp_path)
    fuites = [
        s for i in range(200)
        if "gateway" in (s := eng.substitute_value("HOSTNAME", f"gateway-{i:03d}.internal"))
    ]
    assert not fuites, f"{len(fuites)} substituts reprennent « gateway » : {fuites[:3]}"


@pytest.mark.parametrize("valeur", ["   ", "\n\t", "/", "//"])
def test_chemin_degenere_ne_boucle_pas(tmp_path, valeur):
    assert engine(tmp_path).substitute_value("FILE_PATH", valeur) == valeur


def test_url_ipv6_entre_crochets_reste_valide(tmp_path):
    import ipaddress
    out = engine(tmp_path).substitute_value("URL", "https://[fd00:1234:5678:9abc::1]:8443/x")
    literal = out.split("[", 1)[1].split("]", 1)[0]
    assert ipaddress.ip_address(literal).version == 6
    assert ":8443/" in out and "fd00:1234" not in out


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
