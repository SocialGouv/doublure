"""Contrat entre le détecteur et la classification.

Le détecteur et le moteur vivent dans deux processus (frontière D7) : rien ne
garantit que les noms de types coïncident. Ils ont divergé — les recognizers
regroupent plusieurs motifs sous un seul `supported_entity` (`CERTIFICATE`,
`CRYPTOGRAPHIC_KEY`, `PASSWORD`, `USERNAME`), alors que la table classait les
noms de motifs individuels. Résultat : ces quatre types tombaient dans le
défaut INFRA, donc RÉVERSIBLES et stockés dans le coffre. D4 cassé en silence,
sans qu'aucun test ne bronche.

Ce test ferme la divergence. Il tourne sans le service : la liste des types
est figée ici, et comparée à celle du détecteur quand il est joignable.
"""
from __future__ import annotations

import pytest

from anonproxy.surrogates.classes import CLASS_OF, DataClass, class_of

#: Types émis par `/detect` (stratégie `filtered`, modèle SecureModernBERT).
#: Relevé le 2026-08-02 par `get_supported_entities("filtered")`.
TYPES_EMIS = {
    "AUTH_TOKEN", "CAMPAIGN", "CERTIFICATE", "CERT_SERIAL", "CPE_STRING",
    "CREDIT_CARD", "CRYPTOGRAPHIC_KEY", "CVE_ID", "EMAIL_ADDRESS", "FILE_PATH",
    "HASH", "HOSTNAME", "IP_ADDRESS", "LOCATION", "MAC_ADDRESS", "MALWARE",
    "MITRE_TACTIC", "OID", "ORGANIZATION", "PASSWORD", "PGP_BLOCK",
    "PHONE_NUMBER", "PLATFORM", "PORT", "PRODUCT", "REGISTRY_KEY", "SECTOR",
    "SERVICE", "THREAT_ACTOR", "TOOL", "URL", "USERNAME", "UUID",
}

#: Types dont la mauvaise classification serait une violation de D4.
DOIVENT_ETRE_SECRET = {
    "AUTH_TOKEN", "CERTIFICATE", "CRYPTOGRAPHIC_KEY", "PASSWORD", "PGP_BLOCK",
    "CREDIT_CARD",
}


def types_custom() -> set[str]:
    """Types déclarés dans `config/custom_patterns.json`.

    Dérivés du fichier, pas figés : un motif ajouté par jo doit lui aussi
    recevoir une classe explicite, sinon il tombe dans le défaut.
    """
    import json
    from pathlib import Path

    p = Path(__file__).resolve().parents[1] / "config" / "custom_patterns.json"
    return {
        e["entity_type"] for e in json.loads(p.read_text(encoding="utf-8"))
        if "entity_type" in e
    }


@pytest.mark.parametrize("etype", sorted(types_custom()))
def test_chaque_type_custom_est_classe(etype):
    assert etype in CLASS_OF, (
        f"{etype} est déclaré dans config/custom_patterns.json mais n'a pas de "
        f"classe : il tombe dans le défaut {class_of(etype).value}."
    )


@pytest.mark.parametrize("etype", sorted(TYPES_EMIS))
def test_chaque_type_emis_est_classe_explicitement(etype):
    """Pas de retombée silencieuse sur `DEFAULT_CLASS` pour un type CONNU."""
    assert etype in CLASS_OF, (
        f"{etype} est émis par le détecteur mais absent de CLASS_OF : il tombe "
        f"dans le défaut {class_of(etype).value}, ce qui peut le rendre "
        "réversible alors qu'il ne devrait pas l'être."
    )


@pytest.mark.parametrize("etype", sorted(DOIVENT_ETRE_SECRET))
def test_les_secrets_sont_classes_secret(etype):
    assert class_of(etype) is DataClass.SECRET, \
        f"{etype} n'est pas classé SECRET : il serait stocké et restaurable (D4)"


def test_la_liste_suit_le_detecteur():
    """Si le détecteur tourne, sa liste doit correspondre à celle figée ici.

    Une divergence signifie qu'un type est apparu (modèle, configuration,
    custom pattern) sans avoir été classé.
    """
    import httpx

    try:
        r = httpx.get("http://127.0.0.1:9000/healthz", timeout=2.0)
        r.raise_for_status()
    except (httpx.HTTPError, OSError):
        pytest.skip("détecteur non démarré")

    nb = r.json().get("entity_types")
    attendu = len(TYPES_EMIS | types_custom())
    assert nb == attendu, (
        f"le détecteur annonce {nb} types, le contrat en connaît {attendu} : "
        "un type est apparu sans avoir été classé. Relever la liste avec "
        "`get_supported_entities('filtered')` et compléter CLASS_OF."
    )


def test_le_detecteur_compte_ce_qu_une_regle_de_forme_rend_public():
    """Le résidu des règles `re:` ne doit pas être SILENCIEUX.

    Une entrée EXACTE est une décision prise token par token ; une règle de
    FORME est une heuristique, et `README.md` lui est indiscernable d'un
    domaine `acme.md`. C'est la seule catégorie dont l'échec ne laisse aucune
    trace — ni entrée de coffre, ni substitut non résolu. Elle est donc
    comptée, dédoublonnée par valeur.
    """
    import httpx

    try:
        r = httpx.post("http://127.0.0.1:9000/detect", timeout=20.0,
                       json={"text": "Relis CLAUDE.md puis ouvre infra.md",
                             "strategy": "filtered"})
        r.raise_for_status()
    except (httpx.HTTPError, OSError):
        pytest.skip("détecteur non démarré")

    corps = r.json()
    publics = {p["value"] for p in corps["public_by_shape"]}
    assert publics == {"CLAUDE.md", "infra.md"}, corps["public_by_shape"]
    # Dédoublonné : le même token reçoit plusieurs spans (HOSTNAME, URL…), et
    # les compter donnerait un chiffre sans rapport avec le nombre
    # d'identifiants réellement rendus publics.
    assert len(corps["public_by_shape"]) == 2, corps["public_by_shape"]
    assert all(p["types"] for p in corps["public_by_shape"])
