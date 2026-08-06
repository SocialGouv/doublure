"""Non-régressions issues de la revue adversariale (3 agents, effort max).

Chaque test correspond à une faille PROUVÉE par la revue puis corrigée. Ils
existent pour qu'aucune ne puisse revenir silencieusement.
Données synthétiques uniquement.
"""
from __future__ import annotations


import ipaddress
import pytest


from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.surrogates.overlap import resolve_overlaps
from anonproxy.vault import Vault

MASTER = "ab" * 32


def engine(tmp_path, scope="project:rt") -> SurrogateEngine:
    return SurrogateEngine(vault=Vault(tmp_path / "v.db", master_key=MASTER), master_key=MASTER, scope_key=scope)


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
    # …et les spans retenus ne se chevauchent plus : sans cette assertion, une
    # fonction identité (qui ne résout rien) satisferait le test.
    ordonnes = sorted(kept, key=lambda s: s["start"])
    for a, b in zip(ordonnes, ordonnes[1:]):
        assert a["end"] <= b["start"], f"chevauchement résiduel : {a} / {b}"


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

    eng = SurrogateEngine(vault=Vault(tmp_path / "v.db", master_key=MASTER), master_key=MASTER,
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


# --------------------------------------------------------------------------- #
# Revue R1 — classification, blocs longs, fragments vides
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("etype,valeur", [
    ("PASSWORD", "password=CorrectHorseBatteryStapleV42"),
    ("CRYPTOGRAPHIC_KEY", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"),
    ("CERTIFICATE", "-----BEGIN CERTIFICATE-----\nMIIBogIBAAJBAKj3\n-----END CERTIFICATE-----"),
    ("AUTH_TOKEN", "ghp_syntheticDemoToken1234567890abcd"),
])
def test_secrets_reels_du_detecteur_non_reversibles(tmp_path, etype, valeur):
    """Les types RÉELLEMENT émis par le détecteur (`PASSWORD`,
    `CRYPTOGRAPHIC_KEY`, `CERTIFICATE`) n'étaient pas classés : ils tombaient
    dans le défaut INFRA, donc stockés au coffre et RESTAURABLES. D4 cassé."""
    eng = engine(tmp_path)
    faux = eng.substitute_value(etype, valeur)
    assert faux != valeur
    assert faux not in eng.surrogates_view(), f"{etype} est réversible : D4 violé"
    assert valeur not in eng.surrogates_view().values()
    assert not eng.vault.real_exists("project:rt", valeur)


def test_fragment_sans_alphanumerique_non_enregistre(tmp_path):
    """Un fragment vide de sens (un saut de ligne issu d'un arbitrage) créait
    une correspondance vers la chaîne VIDE : le substitut, s'il était cité par
    le modèle, disparaissait de la réponse rendue à l'opérateur."""
    eng = engine(tmp_path)
    for fragment in ("\n", "  ", "\n\n", "---"):
        assert eng.substitute_value("CERTIFICATE", fragment) == fragment
    assert "" not in eng.surrogates_view().values(), "correspondance vers la chaîne vide"


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


# --------------------------------------------------------------------------- #
# Round 3 — un span PUBLIC n'est pas substitué : s'il gagne un arbitrage de
# recouvrement, la zone sort EN CLAIR. `SERVICE` couvre souvent plus large que
# `HOSTNAME` (« db-master.acme.internal running »), donc le critère de longueur
# le faisait gagner.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("texte, spans, reel", [
    ("db-master.acme.internal running",
     [{"type": "SERVICE", "start": 0, "end": 31, "score": 0.9},
      {"type": "HOSTNAME", "start": 0, "end": 23, "score": 0.9}],
     "db-master.acme.internal"),
    ("db-master.acme.internal",
     [{"type": "SERVICE", "start": 0, "end": 23, "score": 0.9},
      {"type": "HOSTNAME", "start": 0, "end": 23, "score": 0.9}],
     "db-master.acme.internal"),
    ("10.1.2.3:8080",
     [{"type": "PORT", "start": 0, "end": 13, "score": 0.9},
      {"type": "IP_ADDRESS", "start": 0, "end": 8, "score": 0.9}],
     "10.1.2.3"),
])
def test_un_span_public_ne_masque_pas_une_classe_substituable(tmp_path, texte, spans, reel):
    sortie = engine(tmp_path).transform(texte, spans)
    assert reel not in sortie, f"valeur réelle laissée en clair par un span PUBLIC : {sortie!r}"


def test_le_public_reste_prioritaire_sur_ce_qu_il_est_seul_a_couvrir(tmp_path):
    """Le pendant : hors recouvrement, un span PUBLIC garde son rôle."""
    texte = "CVE-2024-3094 sur db-01.acme.internal"
    spans = [{"type": "CVE_ID", "start": 0, "end": 13, "score": 0.9},
             {"type": "HOSTNAME", "start": 18, "end": 37, "score": 0.9}]
    sortie = engine(tmp_path).transform(texte, spans)
    assert sortie.startswith("CVE-2024-3094"), "un identifiant public a été substitué"
    assert "db-01.acme.internal" not in sortie


# --------------------------------------------------------------------------- #
# Round 3 — le NOM d'un paramètre de query n'était jamais substitué. Un nom
# d'API ne contient ni point, ni arobase, ni deux-points : quand il en porte,
# c'est la donnée elle-même.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("url, reel", [
    ("http://api.example.com/foo?db-master-01.acme.internal=1", "db-master-01.acme.internal"),
    ("http://api.example.com/foo?alice@acme.example=x", "alice@acme.example"),
    ("http://api.example.com/foo?10.1.2.3=host", "10.1.2.3"),
    ("http://api.example.com/foo?a=1&fd00::1=2", "fd00::1"),
])
def test_nom_de_parametre_porteur_d_identifiant_substitue(tmp_path, url, reel):
    sortie = engine(tmp_path).substitute_value("URL", url)
    assert reel not in sortie, f"identifiant laissé en clair dans un nom de query : {sortie!r}"


def test_les_noms_de_parametres_d_api_restent_lisibles(tmp_path):
    """Substituer `page` ou `limit` casserait le sens que le modèle doit lire."""
    sortie = engine(tmp_path).substitute_value(
        "URL", "http://api.example.com/foo?page=2&limit=10&cursor=abc")
    for nom in ("page=", "limit=", "cursor="):
        assert nom in sortie, f"nom de paramètre d'API perdu : {nom} ({sortie!r})"


# --------------------------------------------------------------------------- #
# Round 3 — `PASSWORD_CONTEXT` : `.*?[:=]\s*(\S+)$` se cale sur le DERNIER mot,
# donc tout ce qui précède (y compris un premier secret) était recopié.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("valeur, interdits", [
    ("oldpass=secret123ABC newpass=secret456XYZ", ["secret123ABC", "secret456XYZ"]),
    ("jdbc:postgresql://hote/db?password=P@ssword123 ssl=true", ["P@ssword123"]),
    ("password: MonMotDePasse42", ["MonMotDePasse42"]),
    # un identifiant en position de libellé : le span SECRET a fait perdre son
    # span au HOSTNAME, on ne peut donc pas le recopier
    ("db-01.acme.internal pass: X9", ["db-01.acme.internal"]),
])
def test_password_context_ne_recopie_aucun_secret(tmp_path, valeur, interdits):
    sortie = engine(tmp_path).substitute_value("PASSWORD_CONTEXT", valeur)
    for interdit in interdits:
        assert interdit not in sortie, f"{interdit!r} recopié dans {sortie!r}"


def test_password_context_garde_un_libelle_simple(tmp_path):
    """D1 : le substitut reste plausible quand le libellé est inoffensif."""
    assert engine(tmp_path).substitute_value(
        "PASSWORD_CONTEXT", "password: MonMotDePasse42").startswith("password: ")


# --------------------------------------------------------------------------- #
# Round 3 — `_extract_repo` testait une sous-chaîne : `attacker-github.com`
# passait pour du GitHub, et le substitut affichait `github.com`. Ce n'est pas
# une fuite mais une confiance FABRIQUÉE, que le modèle peut lire.
# --------------------------------------------------------------------------- #


def test_un_hote_qui_contient_github_n_est_pas_github(tmp_path):
    from anonproxy.surrogates.canonical import _extract_repo
    assert _extract_repo("https://attacker-github.com/acme/secret-repo") is None
    sortie = engine(tmp_path).substitute_value(
        "URL", "https://attacker-github.com/acme/secret-repo")
    assert "github.com" not in sortie, f"hôte d'hébergement fabriqué : {sortie!r}"


@pytest.mark.parametrize("url", [
    "https://github.com/acme/payments-api",
    "git@github.com:acme/payments-api.git",
    "https://internal.github.com/acme/payments-api",
])
def test_les_vraies_formes_de_depot_restent_reconnues(url):
    from anonproxy.surrogates.canonical import _extract_repo
    assert _extract_repo(url) == ("acme", "payments-api"), url


# --------------------------------------------------------------------------- #
# Round 4 — deux plantages introduits en resserrant `_extract_repo` : l'autorité
# est minuscule mais `re.split` ne l'était pas, et une URL réduite à l'hôte n'a
# rien à découper. `IndexError` n'est pas rattrapé par le proxy → 500.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("url, attendu", [
    ("https://GitHub.com/acme/payments-api", ("acme", "payments-api")),
    ("https://GITHUB.COM/acme/payments-api", ("acme", "payments-api")),
    ("git@GitHub.com:acme/payments-api.git", ("acme", "payments-api")),
    ("https://Internal.GitHub.com/acme/payments-api", ("acme", "payments-api")),
    # l'hôte seul n'est pas un dépôt, et ne doit pas lever
    ("https://github.com", None),
    ("https://GitHub.com", None),
    # le port n'est pas l'organisation
    ("https://github.com:443/acme/payments-api", ("acme", "payments-api")),
])
def test_extraction_de_depot_insensible_a_la_casse(url, attendu):
    from anonproxy.surrogates.canonical import _extract_repo
    assert _extract_repo(url, "URL") == attendu


@pytest.mark.parametrize("valeur", ["example.com/", "acme.internal/",
                                    "portail.acme.internal/"])
def test_un_hote_nu_avec_slash_final_ne_provoque_pas_de_collision(tmp_path, valeur):
    """`hôte/` sans schéma tombait à côté de la normalisation et réclamait le
    substitut DÉJÀ pris par l'hôte : collision insoluble, 503 en session."""
    sortie = engine(tmp_path).substitute_value("URL", valeur)
    assert sortie and valeur.rstrip("/") not in sortie


def test_la_forme_courte_org_depot_ne_vaut_que_pour_un_depot():
    """`example.com/api` est un chemin relatif, pas un dépôt clonable."""
    from anonproxy.surrogates.canonical import _extract_repo
    assert _extract_repo("example.com/api", "URL") is None
    assert _extract_repo("admin/config", "URL") is None
    assert _extract_repo("torvalds/linux", "REPO") == ("torvalds", "linux")


@pytest.mark.parametrize("url, reel", [
    # `name=` : `eq` est vrai mais `value` vide — les deux branches rataient
    ("https://api.example.com/?db-01.acme.internal=", "db-01.acme.internal"),
    ("https://api.example.com/?alice@acme.example=", "alice@acme.example"),
    ("https://api.example.com/?a&db.acme.internal=", "db.acme.internal"),
    # percent-encoding : `%2E` est un point, `%40` une arobase
    ("https://api.example.com/?db-01%2Eacme%2Einternal=1", "db-01%2Eacme%2Einternal"),
    ("https://api.example.com/?alice%40acme%2Eexample=1", "alice%40acme%2Eexample"),
])
def test_nom_de_query_sans_valeur_ou_encode_est_substitue(tmp_path, url, reel):
    sortie = engine(tmp_path).substitute_value("URL", url)
    assert reel not in sortie, f"identifiant laissé dans un nom de query : {sortie!r}"


# --------------------------------------------------------------------------- #
# Round 5 — `_strip_userinfo` ne traitait que les URL à schéma. La forme SSH
# `user:jeton@hôte:chemin` porte les mêmes identifiants et les faisait entrer
# dans la clé du coffre (D4).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("url, secret", [
    ("oauth2:ghp_JetonSynthetique12345@github.com:mon-org/depot", "ghp_JetonSynthetique12345"),
    ("admin:MotDePasseSynth2@github.com:projet/depot", "MotDePasseSynth2"),
])
def test_les_identifiants_ssh_n_entrent_pas_dans_le_coffre(url, secret):
    from anonproxy.surrogates.canonical import _strip_userinfo
    assert secret not in _strip_userinfo(url)
    assert "github.com" in _strip_userinfo(url), "l'hôte doit survivre au nettoyage"


def test_une_forme_ssh_sans_identifiants_reste_intacte():
    from anonproxy.surrogates.canonical import _strip_userinfo
    assert _strip_userinfo("github.com:org/depot") == "github.com:org/depot"


@pytest.mark.parametrize("url, attendu", [
    # La reconnaissance de l'hôte était sensible à la casse alors que
    # `_extract_repo` ne l'est plus : l'URL retombait sur la forme courte
    # `org/dépôt`, que le modèle lit comme un dépôt local (D1).
    ("https://GitHub.com/Acme/PaymentsAPI", "https://github.com/"),
    ("http://github.com/acme/repo", "http://github.com/"),
    ("https://github.com/acme/repo", "https://github.com/"),
    ("git@github.com:acme/repo.git", "git@github.com:"),
])
def test_la_forme_de_l_url_de_depot_est_preservee(tmp_path, url, attendu):
    assert engine(tmp_path).substitute_value("URL", url).startswith(attendu)


@pytest.mark.parametrize("span", [
    {"type": "HOSTNAME", "start": 0, "end": 4, "score": None},
    {"start": 0, "end": 4, "score": 0.9},                      # type absent
    {"type": "HOSTNAME", "start": 0, "end": 4, "score": True},  # bool ≠ score
    {"type": ["HOSTNAME"], "start": 0, "end": 4, "score": 0.9},
])
def test_un_span_mal_forme_leve_une_erreur_rattrapee(tmp_path, span):
    """`TypeError`/`KeyError` ne sont PAS rattrapés par le proxy : 500 non
    structuré et session interrompue, au lieu du fail-closed prévu."""
    with pytest.raises(ValueError):
        engine(tmp_path).transform("abcd", [span])


@pytest.mark.parametrize("valeur", ["sha256:", "md5:", "sha1:"])
def test_un_prefixe_de_hash_sans_corps_ne_bloque_pas_la_requete(tmp_path, valeur):
    """Le substitut valait le réel, les 64 tentatives échouaient → 503."""
    sortie = engine(tmp_path).substitute_value("HASH", valeur)
    assert sortie.startswith(valeur) and len(sortie) > len(valeur)


# --------------------------------------------------------------------------- #
# Round 8 — la règle d'extension de `config/allowlist.txt` est la SEULE de la
# boucle qui rende des valeurs PUBLIQUES : son mode d'échec est une fuite
# silencieuse, sans entrée de coffre ni substitut non résolu pour la signaler.
# Écrite avec `[\w.-]+` comme radical, elle rendait public tout ce qui se
# termine par une de ces extensions — hôtes internes et IP compris.
# --------------------------------------------------------------------------- #

from anonproxy.allowlist import Allowlist


@pytest.mark.parametrize("valeur", [
    # radical à PLUSIEURS labels : c'est un identifiant, pas un fichier
    "db-prod-01.acme.md",
    "srv-billing-prod.acme.internal.conf",
    "api.acme.corp.json",
    "com.acme.billing.SecretClient.kt",
    "public-service.acme.ml",
    "billing.acme.py",
    "api.company.rs",
    "10.0.0.5.log",
    "192.168.5.9.log",
])
def test_un_identifiant_a_plusieurs_labels_n_est_pas_public(valeur):
    assert not Allowlist.load()(valeur), (
        f"{valeur!r} rendu public : il sortirait en clair, sans trace")


@pytest.mark.parametrize("valeur", [
    "infra.md", "README.md", "CLAUDE.md", "nginx.conf", "test_foo.py",
    "settings.json", "docker-compose.yml", "Cargo.lock", "notes.txt",
])
def test_un_nom_de_fichier_simple_reste_public(valeur):
    """Sinon l'agent ne retrouve plus le fichier que l'opérateur lui désigne."""
    assert Allowlist.load()(valeur), f"{valeur!r} serait substitué"


# --------------------------------------------------------------------------- #
# Round 9 — l'allowlist est partagée avec les SOUS-PARTIES d'une valeur
# composite (tag d'image, segment d'URL). Une entrée EXACTE est une décision
# prise token par token, elle vaut partout ; une règle de FORME suppose un
# contexte que la sous-partie n'a pas — celle des noms de fichiers laissait
# sortir `tenant-acme-nda.md` au milieu d'une URL par ailleurs pseudonymisée.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("url, sensible", [
    ("https://internal.acme.example/tenant-acme-nda.md", "tenant-acme-nda.md"),
    ("https://intranet.corp/download/customer-abc-contract.pdf",
     "customer-abc-contract.pdf"),
    ("https://vcs.internal/repo/client-nda-2025.zip", "client-nda-2025.zip"),
])
def test_un_segment_d_url_n_est_pas_couvert_par_une_regle_de_forme(tmp_path, url, sensible):
    from anonproxy.allowlist import Allowlist
    from anonproxy.surrogates.engine import SurrogateEngine
    eng = SurrogateEngine(vault=Vault(tmp_path / "v.db", master_key=MASTER),
                          master_key=MASTER, scope_key="project:r9",
                          is_public=Allowlist.load().is_exact)
    assert sensible not in eng.substitute_value("URL", url)


@pytest.mark.parametrize("image, sensible", [
    ("registry.internal.acme/payments:tenant-nda-v1.tar", "tenant-nda-v1.tar"),
    ("registry.internal.acme/payments:branch-feat-payment-fix.log",
     "branch-feat-payment-fix.log"),
    ("registry.internal.acme/payments:client-report-2025.md", "client-report-2025.md"),
])
def test_un_tag_d_image_n_est_pas_couvert_par_une_regle_de_forme(tmp_path, image, sensible):
    from anonproxy.allowlist import Allowlist
    from anonproxy.surrogates.engine import SurrogateEngine
    eng = SurrogateEngine(vault=Vault(tmp_path / "v.db", master_key=MASTER),
                          master_key=MASTER, scope_key="project:r9",
                          is_public=Allowlist.load().is_exact)
    assert sensible not in eng.substitute_value("CONTAINER_IMAGE", image)


def test_une_entree_exacte_vaut_toujours_pour_une_sous_partie(tmp_path):
    """Le pendant : c'est l'intention documentée du partage de l'allowlist."""
    from anonproxy.surrogates.engine import SurrogateEngine
    eng = SurrogateEngine(vault=Vault(tmp_path / "v.db", master_key=MASTER),
                          master_key=MASTER, scope_key="project:r9",
                          is_public=lambda v: v in {"python3.12-slim", "healthz"})
    assert eng.substitute_value(
        "CONTAINER_IMAGE", "registry.acme.io/app:python3.12-slim").endswith(
            ":python3.12-slim")


# --------------------------------------------------------------------------- #
# Round 10 — le résidu de la règle d'extensions, ÉNONCÉ plutôt que supposé
#
# La restriction du radical à un seul label borne la fuite, elle ne la supprime
# pas : plusieurs de ces extensions sont des ccTLD réellement enregistrables.
# Un domaine externe d'un seul label sort donc en clair. Ce test n'est pas une
# validation, c'est le CONSTAT verrouillé : s'il se met à échouer, c'est que
# l'arbitrage a changé et que la documentation doit suivre.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("valeur", ["partenaire.md", "billing.py", "core.rs"])
def test_residu_un_domaine_externe_d_un_seul_label_reste_public(valeur):
    """Le prix payé pour que `main.py` et `README.md` restent lisibles."""
    assert Allowlist.load()(valeur)


@pytest.mark.parametrize("valeur", ["acme.pl", "partenaire.ml", "srv.pl"])
def test_les_ccTLD_a_vrai_volume_ont_ete_retires_de_la_regle(valeur):
    """`.pl` (Pologne) et `.ml` (Mali) désignent aussi du Perl et de l'OCaml.

    Arbitrage de jo : ce sont les deux ccTLD de la liste à porter un vrai
    volume de domaines, et leur valeur comme extension de fichier est faible
    ici. L'arbitrage se rejuge extension par extension, pas en bloc.
    """
    assert not Allowlist.load()(valeur), (
        f"{valeur!r} rendu public : il sortirait en clair, sans trace")


@pytest.mark.parametrize("valeur", [
    "db-01.acme.internal", "srv-billing.acme.pl", "api.acme.md",
])
def test_un_hote_multi_labels_n_est_jamais_public_meme_sur_ces_ccTLD(valeur):
    """La contrepartie : les hôtes internes sont multi-labels, donc couverts."""
    assert not Allowlist.load()(valeur), (
        f"{valeur!r} rendu public : il sortirait en clair, sans trace")


# --------------------------------------------------------------------------- #
# Round 11 — la queue LIBRE des règles de forme
#
# Le round 8 avait fermé cette classe pour la règle d'extensions : une règle
# `re:` ne doit pas rendre public un identifiant à PLUSIEURS labels, car les
# labels supplémentaires portent le nom d'organisation. La même queue libre
# subsistait ailleurs — chemins d'import Go, chemins d'URL, chemins d'image —
# et celles-là acceptaient le tiret, donc un vrai nom d'hôte y entrait.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("valeur", [
    # chemins d'URL
    "https://json-schema.org/db-01.acme.internal/schema",
    "https://docs.anthropic.com/srv-billing-prod.acmecorp.internal",
    "https://github.com/anthropics/tenant-nda-acme.internal.corp/prive",
    # chemins d'import Go
    "k8s.io/db-01.acme.internal",
    "golang.org/x/srv-billing-prod.acmecorp.internal",
    "sigs.k8s.io/db-01.acme.internal/pkg",
    # chemins d'image
    "registry.k8s.io/db-01.acme.internal/app",
    "mcr.microsoft.com/srv-billing-prod.acmecorp.internal",
    "gcr.io/distroless/tenant-acme-nda.internal",
    "docker.io/library/db-01.acme.internal",
])
def test_une_regle_de_forme_ne_rend_pas_public_un_chemin_multi_labels(valeur):
    assert not Allowlist.load()(valeur), (
        f"{valeur!r} rendu public : il sortirait en clair")


@pytest.mark.parametrize("valeur", [
    "https://json-schema.org/draft/2020-12/schema",
    "https://docs.anthropic.com/en/api/messages",
    "https://github.com/anthropics/claude-code",
    "k8s.io/api/core/v1",
    "golang.org/x/net/http2",
    "sigs.k8s.io/controller-runtime",
    "docker.io/library/postgres:16",
    "registry.k8s.io/pause:3.9",
    "gcr.io/distroless/static-debian12:nonroot",
])
def test_le_resserrement_ne_casse_pas_les_valeurs_publiques_legitimes(valeur):
    """Substituer une URL de standard ou une image publique casse le protocole
    ou prive le modèle d'une référence qu'il sait lire."""
    assert Allowlist.load()(valeur), f"{valeur!r} serait substitué à tort"


@pytest.mark.parametrize("valeur", [
    # Prix du resserrement : un segment de chemin ne porte plus AUCUN point,
    # donc un nom de fichier dans une URL de documentation est substitué.
    # `acme.internal` a exactement la forme d'`index.html` — la borne « un
    # seul point » ne les distinguait pas. Une URL de doc abîmée est visible
    # et cosmétique ; un hôte interne qui sort ne l'est pas.
    "https://docs.anthropic.com/guide/index.html",
    "https://spdx.org/licenses/MIT.html",
])
def test_prix_du_resserrement_un_nom_de_fichier_dans_une_url(valeur):
    assert not Allowlist.load()(valeur)


@pytest.mark.parametrize("valeur", [
    "sigs.k8s.io/tenant-acme-nda/prive",
    "org.apache.kafka.streams.internal.acme.PaymentsClient",
])
def test_residu_un_segment_d_un_seul_label_sous_un_prefixe_public(valeur):
    """Résidu ASSUMÉ, compté par `public_by_shape`.

    Un segment d'un seul label sous un préfixe public est indiscernable d'un
    vrai module (`sigs.k8s.io/controller-runtime`) ou d'un vrai paquet
    (`org.apache.kafka.streams.KafkaStreams`). Les paquets Java n'acceptent en
    outre pas le tiret, ce qui exclut la plupart des noms d'hôtes internes.
    """
    assert Allowlist.load()(valeur)


# --------------------------------------------------------------------------- #
# Round 12 — les règles de paquets épinglent un préfixe TIERS
#
# Arbitrage de jo : garder la pertinence sur les vraies bibliothèques, couper
# dès que la valeur est spécifique au dépôt. `javax.` était la seule règle à
# n'épingler aucun second niveau, alors que l'espace de noms est RÉSERVÉ : tout
# ce qui s'y trouve hors des paquets normalisés est, par définition, à nous.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("valeur", [
    "org.apache.kafka.streams.KafkaStreams",
    "org.apache.commons.lang3.StringUtils",
    "com.google.common.collect.ImmutableList",
    "io.netty.channel.ChannelHandler",
    "javax.servlet.http.HttpServletRequest",
    "javax.persistence.EntityManager",
    "javax.crypto.Cipher",
])
def test_une_api_publique_reste_lisible_par_le_modele(valeur):
    assert Allowlist.load()(valeur), f"{valeur!r} substitué : le modèle perd la référence"


@pytest.mark.parametrize("valeur", [
    # le paquet propre à l'opérateur ne correspond à aucun préfixe tiers
    "com.acme.billing.PaymentsClient",
    "com.acmecorp.payments.Client",
    # espace de noms RÉSERVÉ : ce qui n'y est pas normalisé est à nous
    "javax.acme.internal.SecretService",
    "javax.acmecorp.PaymentsClient",
])
def test_un_paquet_specifique_au_depot_n_est_pas_public(valeur):
    assert not Allowlist.load()(valeur), (
        f"{valeur!r} rendu public : il sortirait en clair")


@pytest.mark.parametrize("valeur", [
    "org.apache.kafka.acme.internal.Foo",
    "com.google.cloud.acme.internal.Client",
])
def test_residu_un_identifiant_interne_sous_un_prefixe_tiers(valeur):
    """Résidu ASSUMÉ, compté par `public_by_shape`.

    Un paquet est pointé par nature : la borne « pas de point » qui ferme les
    chemins ne s'applique pas ici. Trancher demanderait de savoir que `acme`
    est à nous et `streams` non — une question d'INVENTAIRE, pas de forme.
    """
    assert Allowlist.load()(valeur)


# --------------------------------------------------------------------------- #
# Round 15 — utilité et plausibilité (D1), sans effet sur la protection
#
# Ces deux défauts ne faisaient sortir aucune valeur réelle. Ils privaient le
# modèle d'une référence qu'il sait lire, ce qui est un manquement à D1 :
# un substitut doit être PLAUSIBLE, donc de même nature que l'original.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("valeur, variante", [
    ("localhost", "Localhost"),
    ("localhost", "LOCALHOST"),
    ("github.com/spf13/cobra", "GitHub.com/spf13/cobra"),
    ("sts.amazonaws.com", "STS.amazonaws.com"),
    ("kube-system", "Kube-System"),
])
def test_une_entree_en_minuscules_est_insensible_a_la_casse(valeur, variante):
    """Un nom d'hôte ou un chemin d'import ne dépend pas de la casse.

    Substituer `GitHub.com/spf13/cobra` ne protégeait rien — Anthropic ne
    voyait ni l'une ni l'autre forme — et privait le modèle de la référence.
    """
    from anonproxy.allowlist import Allowlist
    liste = Allowlist.load()
    assert liste(valeur) and liste(variante), variante


def test_une_entree_avec_majuscule_reste_sensible_a_la_casse():
    """`Mail.Read` est une permission Microsoft Graph, pas un mot : la casse de
    l'entrée déclare elle-même si la casse compte."""
    from anonproxy.allowlist import Allowlist
    liste = Allowlist(exact={"Mail.Read", "localhost"}, patterns=[])
    assert liste("Mail.Read") and not liste("mail.read")
    assert liste("LOCALHOST")


@pytest.mark.parametrize("typ, valeur, prefixe", [
    # Un schéma sans `//` ne porte pas d'autorité : l'arobase d'un `mailto:`
    # sépare le local du domaine, ce n'est pas un userinfo. Le traiter comme
    # tel faisait disparaître le schéma ET le local, et le modèle recevait un
    # nom d'hôte là où il y avait une adresse.
    ("URL", "mailto:alice@acme.internal", "mailto:"),
    ("URL", "data:text/plain;base64,SGVsbG8=", "data:text/plain;base64,"),
])
def test_un_uri_sans_autorite_garde_sa_structure(tmp_path, typ, valeur, prefixe):
    from anonproxy.allowlist import Allowlist
    eng = SurrogateEngine(vault=Vault(tmp_path / "v.db", master_key=MASTER),
                          master_key=MASTER, scope_key="project:r15",
                          is_public=Allowlist.load().is_exact)
    rendu = eng.substitute_value(typ, valeur)
    assert rendu.startswith(prefixe), rendu
    assert "acme" not in rendu and "alice" not in rendu


def test_un_depot_auto_heberge_garde_la_forme_d_une_url(tmp_path):
    """Sans hôte public reconnu, un dépôt retombait sur un simple MOT — que le
    modèle ne peut ni cloner ni lire comme une URL."""
    from anonproxy.allowlist import Allowlist
    eng = SurrogateEngine(vault=Vault(tmp_path / "v.db", master_key=MASTER),
                          master_key=MASTER, scope_key="project:r15",
                          is_public=Allowlist.load().is_exact)
    rendu = eng.substitute_value("REPO", "https://code.acme.internal/team/outil")
    assert rendu.startswith("https://") and rendu.count("/") >= 4, rendu
    for fragment in ("acme", "team", "outil"):
        assert fragment not in rendu, rendu


def test_une_forme_ssh_garde_son_userinfo_retire(tmp_path):
    """Contrôle D4 : l'exemption ne vaut QUE pour les schémas sans autorité."""
    from anonproxy.allowlist import Allowlist
    eng = SurrogateEngine(vault=Vault(tmp_path / "v.db", master_key=MASTER),
                          master_key=MASTER, scope_key="project:r15",
                          is_public=Allowlist.load().is_exact)
    rendu = eng.substitute_value("URL", "https://oauth2:ghp_jeton@github.com/o/d")
    assert "ghp_jeton" not in rendu and "oauth2" not in rendu, rendu


# --------------------------------------------------------------------------- #
# Round 16 — le préfixe d'algorithme d'une empreinte est structurel (D1)
#
# Le restreindre à `sha\d+|md5|blake\d*|crc\d*` perdait `sha3-256`, `SHA-256`,
# `blake2b`, `keccak256`, `xxh64` : l'opérateur voyait un hexadécimal nu, sans
# savoir à quoi il avait affaire. Le registre reste FERMÉ — un préfixe libre
# conserverait `srv-billing-01:deadbeef`, donc une fuite.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("prefixe", [
    "sha256", "sha1", "sha512", "md5", "sha3-256", "SHA-256",
    "blake2b", "blake3", "keccak256", "xxh64", "ripemd160",
])
def test_le_prefixe_d_algorithme_est_conserve(tmp_path, prefixe):
    eng = engine(tmp_path)
    valeur = f"{prefixe}:a3f1b2c4d5e6f7089a1b2c3d4e5f6071"
    assert eng.substitute_value("HASH", valeur).startswith(f"{prefixe}:")


@pytest.mark.parametrize("prefixe", [
    "srv-billing-01", "acme.internal", "db-master-prod", "tenant-acme",
])
def test_un_prefixe_hors_registre_n_est_jamais_conserve(tmp_path, prefixe):
    """Sinon la partie AVANT le deux-points sortirait en clair."""
    eng = engine(tmp_path)
    rendu = eng.substitute_value("HASH", f"{prefixe}:a3f1b2c4d5e6")
    assert prefixe not in rendu, rendu


# --------------------------------------------------------------------------- #
# Notation CIDR — trouvé en SESSION RÉELLE, pas par une revue.
#
# `10.1.2.0/24` n'est pas une adresse : `ip_address` échouait, la valeur
# tombait dans le générique et sortait sous un MOT (`glacier-vault10`). Le
# modèle voyait alors des hôtes dans un réseau fictif et une déclaration de
# sous-réseau qui n'en était pas un — il a signalé une « incohérence » dans
# l'inventaire, à juste titre. Manquement à D1 : le substitut doit rester
# plausible POUR SON TYPE.
# --------------------------------------------------------------------------- #
def test_un_cidr_reste_un_cidr(tmp_path):
    moteur = SurrogateEngine(
        vault=Vault(tmp_path / "cidr.db", master_key=MASTER),
        master_key=MASTER, scope_key="project:cidr")
    faux = moteur.substitute_value("IP_ADDRESS", "10.1.2.0/24")
    assert "/" in faux, faux
    reseau = ipaddress.ip_network(faux, strict=False)   # doit parser
    assert reseau.prefixlen == 24
    assert faux != "10.1.2.0/24"


def test_le_reseau_fictif_contient_ses_hotes_fictifs(tmp_path):
    """La co-appartenance /24 est un attribut PRÉSERVÉ (réponse §3.4).

    Sans ça, le modèle reçoit des adresses et un sous-réseau qui ne les
    contient pas — et raisonne sur une contradiction inexistante.
    """
    moteur = SurrogateEngine(
        vault=Vault(tmp_path / "coherence.db", master_key=MASTER),
        master_key=MASTER, scope_key="project:cidr")
    h1 = moteur.substitute_value("IP_ADDRESS", "10.1.2.3")
    h2 = moteur.substitute_value("IP_ADDRESS", "10.1.2.4")
    reseau = ipaddress.ip_network(
        moteur.substitute_value("IP_ADDRESS", "10.1.2.0/24"), strict=False)
    assert ipaddress.ip_address(h1) in reseau, (h1, reseau)
    assert ipaddress.ip_address(h2) in reseau, (h2, reseau)


def test_un_cidr_v6_reste_un_cidr_v6(tmp_path):
    moteur = SurrogateEngine(
        vault=Vault(tmp_path / "v6.db", master_key=MASTER),
        master_key=MASTER, scope_key="project:cidr")
    hote = moteur.substitute_value("IP_ADDRESS", "2001:db8:1:2::5")
    reseau = ipaddress.ip_network(
        moteur.substitute_value("IP_ADDRESS", "2001:db8:1:2::/64"), strict=False)
    assert reseau.version == 6 and reseau.prefixlen == 64
    assert ipaddress.ip_address(hote) in reseau


def test_une_barre_oblique_qui_n_est_pas_un_reseau_reste_generique(tmp_path):
    """`10.1.2.0/abc` n'est pas un réseau : pas de plantage, substitution."""
    moteur = SurrogateEngine(
        vault=Vault(tmp_path / "pasreseau.db", master_key=MASTER),
        master_key=MASTER, scope_key="project:cidr")
    for bizarre in ("10.1.2.0/abc", "10.1.2.0/", "10.1.2.0/99", "/24"):
        faux = moteur.substitute_value("IP_ADDRESS", bizarre)
        assert faux != bizarre, bizarre


# --------------------------------------------------------------------------- #
# « interne vs externe » — attribut PRÉSERVÉ (§3.4), et il ne l'était pas.
#
# Trouvé par le MODÈLE lui-même, en session réelle, l'annonce activée : il
# voyait une « passerelle publique » adressée en RFC 1918 et a refusé de
# trancher entre « artefact de substitution » et « document ambigu ».
#
# Deux causes : `ipaddress` classe les plages de DOCUMENTATION (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24) en `is_private`, alors qu'elles tiennent la
# place d'adresses routables ; et le générateur IPv6 rendait une ULA `fd…`
# quelle que soit la nature de l'adresse réelle.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("reelle", [
    "10.1.2.3", "172.16.5.9", "192.168.1.1", "fd00::1",          # internes
    "8.8.8.8", "51.15.20.30", "2001:db8::1",                      # publiques
    "198.51.100.42", "192.0.2.5", "203.0.113.9",                  # documentation
    "198.51.100.0/24", "10.1.2.0/24",
])
def test_interne_ou_externe_survit_a_la_substitution(tmp_path, reelle):
    from anonproxy.surrogates.canonical import est_privee

    moteur = SurrogateEngine(
        vault=Vault(tmp_path / "attr.db", master_key=MASTER),
        master_key=MASTER, scope_key="project:attr")
    faux = moteur.substitute_value("IP_ADDRESS", reelle)
    avant = ipaddress.ip_network(reelle, strict=False)
    apres = ipaddress.ip_network(faux, strict=False)
    assert est_privee(avant) == est_privee(apres), (reelle, faux)


def test_une_plage_de_documentation_n_est_pas_un_reseau_interne():
    """C'est la distinction qui manquait : `is_private` ne suffit pas."""
    from anonproxy.surrogates.canonical import est_privee

    assert est_privee(ipaddress.ip_address("10.1.2.3"))
    assert not est_privee(ipaddress.ip_address("198.51.100.42"))
    assert not est_privee(ipaddress.ip_address("2001:db8::1"))
    assert est_privee(ipaddress.ip_address("fd00::1"))


def test_aucun_substitut_ne_designe_la_machine_d_un_tiers(tmp_path):
    """Invariant : un substitut ne doit JAMAIS être une adresse routable.

    Le générateur faisait varier le troisième octet des blocs de documentation
    pour obtenir plusieurs réseaux, et sortait ainsi du réservé :
    `198.51.32.0/24` est alloué et routé. Si le modèle propose une commande
    visant un substitut, elle part chez son propriétaire réel.
    """
    moteur = SurrogateEngine(
        vault=Vault(tmp_path / "routable.db", master_key=MASTER),
        master_key=MASTER, scope_key="project:routable")
    for i in range(400):
        for reelle in (f"51.{i % 256}.{(i * 7) % 256}.10",   # publiques réelles
                       f"10.{i % 256}.{(i * 3) % 256}.5"):   # internes
            faux = ipaddress.ip_network(
                moteur.substitute_value("IP_ADDRESS", reelle), strict=False)
            assert not faux.is_global, (reelle, str(faux))
