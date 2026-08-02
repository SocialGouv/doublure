"""Classification par classe de donnée (plan §5 Phase 2, tâche 3) et table de
priorité des recouvrements (tâche 4).

    | Classe               | Traitement                                    |
    |----------------------|-----------------------------------------------|
    | INFRA                | substitut plausible réversible                |
    | PII                  | substitut plausible réversible                |
    | SECRET               | référence NON réversible (D4)                 |
    | PUBLIC               | allowlist, laissé en clair                    |
    | IAM_PRINCIPAL        | hors MVP (§8) — traité comme INFRA, marqué    |
"""
from __future__ import annotations

from enum import Enum


class DataClass(str, Enum):
    INFRA = "infra"
    PII = "pii"
    SECRET = "secret"
    PUBLIC = "public"
    IAM_PRINCIPAL = "iam_principal"


#: Types AnonShield (+ nos types custom) → classe de donnée.
#:
#: ATTENTION : ce sont les types RÉELLEMENT ÉMIS par `/detect` qui comptent.
#: Les recognizers d'AnonShield regroupent plusieurs motifs sous un seul
#: `supported_entity` : `CERTIFICATE` (et non `CERT_PEM`),
#: `CRYPTOGRAPHIC_KEY` (et non `JWT`/`RSA_MODULUS`), `PASSWORD` (et non
#: `PASSWORD_CONTEXT`), `USERNAME`. Classer les noms de motifs individuels
#: laissait ces quatre types tomber dans le défaut INFRA : mots de passe,
#: jetons JWT et certificats devenaient RÉVERSIBLES et étaient stockés dans le
#: coffre — D4 cassé en silence. `tests/test_classes_contract.py` vérifie
#: désormais que chaque type émis par le détecteur a une classe explicite.
CLASS_OF: dict[str, DataClass] = {
    # -- secrets : jamais réversibles (D4) ---------------------------------- #
    "CERTIFICATE": DataClass.SECRET,        # CERT_PEM, CERT_DER, CERT_REQUEST…
    "CRYPTOGRAPHIC_KEY": DataClass.SECRET,  # JWT, RSA_MODULUS, BASE64_KEY
    "PASSWORD": DataClass.SECRET,
    "AUTH_TOKEN": DataClass.SECRET,
    "PGP_BLOCK": DataClass.SECRET,
    "COOKIE_SESSION": DataClass.SECRET,
    "API_KEY": DataClass.SECRET,
    "CREDIT_CARD": DataClass.SECRET,
    # noms de motifs individuels : jamais émis tels quels, conservés au cas où
    # une configuration les exposerait directement.
    "JWT": DataClass.SECRET,
    "PRIVATE_KEY_PEM": DataClass.SECRET,
    "PASSWORD_CONTEXT": DataClass.SECRET,
    "RSA_MODULUS": DataClass.SECRET,
    "CERT_PEM": DataClass.SECRET,
    "CERT_REQUEST_PEM": DataClass.SECRET,
    "CERT_DER": DataClass.SECRET,
    # -- PII ----------------------------------------------------------------- #
    "EMAIL_ADDRESS": DataClass.PII,
    "PERSON": DataClass.PII,
    "PHONE_NUMBER": DataClass.PII,
    "USERNAME": DataClass.PII,
    "USERNAME_CONTEXT": DataClass.PII,
    "USER_PATH": DataClass.PII,
    "CPF": DataClass.PII,
    # -- identifiants d'infrastructure --------------------------------------- #
    "HOSTNAME": DataClass.INFRA,
    "IP_ADDRESS": DataClass.INFRA,
    "URL": DataClass.INFRA,
    "FQDN": DataClass.INFRA,
    "MAC_ADDRESS": DataClass.INFRA,
    "FILE_PATH": DataClass.INFRA,
    "HASH": DataClass.INFRA,
    "UUID": DataClass.INFRA,
    "ORGANIZATION": DataClass.INFRA,
    "LOCATION": DataClass.INFRA,
    "REPO": DataClass.INFRA,
    "CONTAINER_IMAGE": DataClass.INFRA,
    "K8S_NAMESPACE": DataClass.INFRA,
    "SERVICE_ACCOUNT": DataClass.INFRA,
    "COMMIT_SHA": DataClass.INFRA,
    "CERT_CN": DataClass.INFRA,
    "CERT_SERIAL": DataClass.INFRA,
    "CERT_THUMBPRINT": DataClass.INFRA,
    "HEX_HOSTNAME": DataClass.INFRA,
    # -- public / standard : jamais substitué -------------------------------- #
    "CVE_ID": DataClass.PUBLIC,
    "CPE": DataClass.PUBLIC,
    "CPE_STRING": DataClass.PUBLIC,
    "OID": DataClass.PUBLIC,
    "PORT": DataClass.PUBLIC,
    "MALWARE": DataClass.PUBLIC,
    "THREAT_ACTOR": DataClass.PUBLIC,
    "MITRE_TACTIC": DataClass.PUBLIC,
    "PLATFORM": DataClass.PUBLIC,
    "PRODUCT": DataClass.PUBLIC,
    "TOOL": DataClass.PUBLIC,
    "SECTOR": DataClass.PUBLIC,
    "CAMPAIGN": DataClass.PUBLIC,
    #: `SERVICE` du modèle cyber désigne un logiciel générique (« sshd »,
    #: « nginx ») et se déclenche massivement sur de la prose technique — même
    #: famille que PRODUCT/TOOL/PLATFORM, donc public. Les vrais services
    #: internes restent couverts par HOSTNAME, SERVICE_ACCOUNT et les custom
    #: patterns. À réévaluer sur le corpus doré (Phase 5).
    "SERVICE": DataClass.PUBLIC,
    "REGISTRY_KEY": DataClass.INFRA,
}

#: Type inconnu → INFRA (substitué et réversible). Choix fail-safe : un type
#: nouveau est traité comme sensible plutôt que laissé en clair.
DEFAULT_CLASS = DataClass.INFRA


def class_of(etype: str) -> DataClass:
    return CLASS_OF.get(etype, DEFAULT_CLASS)


#: Priorité des recouvrements (plan §5) :
#: SECRET > IBAN/CB > ID technique > EMAIL > HOSTNAME > IP > NOM.
#: Rang faible = gagne. Deux détecteurs sur la même sous-chaîne se départagent
#: par ce rang AVANT le score, pour un résultat déterministe.
_PRIORITY: dict[str, int] = {
    # secrets
    "PRIVATE_KEY_PEM": 0, "PGP_BLOCK": 0, "CERTIFICATE": 0,
    "JWT": 1, "AUTH_TOKEN": 1, "CRYPTOGRAPHIC_KEY": 1, "PASSWORD": 1,
    "API_KEY": 1, "COOKIE_SESSION": 1, "PASSWORD_CONTEXT": 1, "RSA_MODULUS": 1,
    "CERT_PEM": 1, "CERT_REQUEST_PEM": 1, "CERT_DER": 1,
    # instruments financiers
    "CREDIT_CARD": 2, "IBAN_CODE": 2, "CPF": 2,
    # identifiants techniques
    "UUID": 3, "COMMIT_SHA": 3, "HASH": 3, "CERT_THUMBPRINT": 3, "CERT_SERIAL": 3,
    "MAC_ADDRESS": 3, "CONTAINER_IMAGE": 4, "REPO": 4, "URL": 5, "FILE_PATH": 5,
    "USER_PATH": 5,
    # identités
    "EMAIL_ADDRESS": 6,
    # réseau
    "HOSTNAME": 7, "FQDN": 7, "HEX_HOSTNAME": 7, "CERT_CN": 7,
    "K8S_NAMESPACE": 7, "SERVICE_ACCOUNT": 7,
    "IP_ADDRESS": 8,
    # noms propres (les plus faibles : forte tendance aux faux positifs)
    "PERSON": 9, "ORGANIZATION": 9, "LOCATION": 9, "USERNAME_CONTEXT": 9,
}

DEFAULT_PRIORITY = 6


def priority_of(etype: str) -> int:
    return _PRIORITY.get(etype, DEFAULT_PRIORITY)
