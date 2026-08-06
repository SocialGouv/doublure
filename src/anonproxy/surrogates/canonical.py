"""Résolution canonique (plan §5 Phase 2, tâche 1).

Plusieurs formes d'une même entité doivent mapper sur UN enregistrement :

- dépôt : ``https://github.com/acme/payments-api``, ``git@github.com:acme/payments-api.git``,
  ``acme/payments-api`` → clé canonique ``repo:acme/payments-api`` ;
- hôte : FQDN et nom court → clé ``host:<label>`` par label, la zone étant
  substituée séparément (d'où la cohérence FQDN ↔ nom court) ;
- image : ``registry.acme.io/team/app:1.2`` → dépôt + tag traités séparément.

Le découpage en *composants* est ce qui permet à la fois la cohérence entre
formes et la préservation de la co-appartenance (même zone → même substitut
de zone).
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

#: Suffixes DNS considérés comme « internes » (attribut préservé §3.4).
INTERNAL_SUFFIXES: tuple[str, ...] = (
    ".internal", ".local", ".lan", ".intra", ".corp", ".home.arpa",
    ".svc.cluster.local", ".cluster.local",
)

#: Marqueurs d'environnement préservés dans les substituts (attribut §3.4).
ENV_TOKENS: tuple[str, ...] = (
    "prod", "production", "staging", "stage", "preprod", "uat", "qa",
    "dev", "development", "test", "sandbox", "canary", "demo", "int",
)

_ENV_RE = re.compile(r"(?<![a-z0-9])(" + "|".join(ENV_TOKENS) + r")(?![a-z0-9])", re.I)

#: Forges reconnues pour la résolution canonique des dépôts. Le moteur de
#: substituts s'en sert aussi pour reconstruire l'URL : une seule liste.
REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")

def _is_bare_host(value: str) -> bool:
    """Une « URL » qui n'est qu'un nom d'hôte : ni schéma, ni chemin, ni query.

    C'est le MÊME objet qu'un HOSTNAME et il doit recevoir le même substitut,
    sinon le modèle voit deux machines. La règle porte sur la forme effective,
    pas sur une expression stricte : un span détecté peut traîner des points de
    troncature (`...api.acme.internal`), et le traiter à part créait une
    seconde entrée de coffre pour un substitut déjà pris — conflit d'unicité
    que la régénération ne pouvait pas résoudre.
    """
    return (
        "://" not in value
        and "." in value
        and not any(c in value for c in "/?#@ \t")
    )

#: Suffixes internes du plus long au plus court : `x.svc.cluster.local` doit
#: être reconnu avant `x.local`. Dérivé d'INTERNAL_SUFFIXES, jamais recopié.
INTERNAL_SUFFIXES_LONGEST_FIRST = tuple(sorted(INTERNAL_SUFFIXES, key=len, reverse=True))


@dataclass(frozen=True)
class Canonical:
    """Forme canonique d'une valeur : clé stable + attributs à préserver."""

    key: str                     # identité canonique (entrée du HMAC)
    kind: str                    # host | ip | email | repo | image | generic | …
    attrs: dict[str, str]        # env, internal, subnet, actor…
    normalized: str = ""         # valeur NFC, sans espaces de bord


def env_of(text: str) -> str | None:
    """Marqueur d'environnement présent dans ``text`` (normalisé), sinon None."""
    m = _ENV_RE.search(text)
    if not m:
        return None
    tok = m.group(1).lower()
    return {"production": "prod", "stage": "staging", "development": "dev"}.get(tok, tok)


def is_internal_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h.endswith(sfx) for sfx in INTERNAL_SUFFIXES)


def split_host(host: str) -> tuple[str, str]:
    """(nom court, zone) — ``db-01.acme.internal`` → (``db-01``, ``acme.internal``)."""
    h = host.strip().rstrip(".")
    if "." not in h:
        return h, ""
    short, zone = h.split(".", 1)
    return short, zone


#: Plages de DOCUMENTATION (RFC 5737 et 3849). `ipaddress` les classe
#: `is_private`, alors qu'elles tiennent la place d'adresses PUBLIQUES : elles
#: sont faites pour illustrer un réseau routable dans un document.
#:
#: Sans cette exception, une passerelle publique écrite `198.51.100.42`
#: recevait un substitut en `10.x`, et l'attribut « interne vs externe »
#: — préservé par décision (§3.4) — s'inversait. C'est le modèle lui-même qui
#: l'a signalé en session, l'annonce activée : il voyait une « passerelle
#: publique » adressée en RFC 1918 et a refusé de trancher seul.
#:
#: Ce sont aussi les plages que le moteur ÉMET comme espace public fictif :
#: les traiter comme publiques rend donc la substitution cohérente avec
#: elle-même.
PLAGES_DOCUMENTATION = (
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),     # documentation IPv6
    # RFC 2544, bancs d'essai : c'est l'espace public FICTIF qu'émet le moteur.
    # L'y inclure garde la substitution cohérente avec elle-même — un substitut
    # public doit se relire comme public.
    ipaddress.ip_network("198.18.0.0/15"),
)


def est_privee(adresse) -> bool:
    """« Cette adresse est-elle sur un réseau INTERNE ? »

    Prend une adresse ou un réseau. Ni `is_private` ni `is_global` ne répondent
    seuls : la première range les plages de documentation avec le RFC 1918, la
    seconde exclut aussi le loopback et le lien-local, qui sont bien internes.
    """
    for plage in PLAGES_DOCUMENTATION:
        if adresse.version != plage.version:
            continue
        reseau = adresse if isinstance(adresse, (ipaddress.IPv4Network,
                                                 ipaddress.IPv6Network)) \
            else ipaddress.ip_network(f"{adresse}/{adresse.max_prefixlen}")
        if reseau.subnet_of(plage):
            return False
    return adresse.is_private


def canonicalize(etype: str, value: str) -> Canonical:
    # NFC : « café » composé et décomposé désignent la même entité et doivent
    # produire le même substitut, sinon deux identités fictives coexistent.
    # Attention : ce n'est PAS une normalisation d'homoglyphes — `аcme` en
    # cyrillique reste une entité distincte, et doit le rester (sinon deux
    # réels différents partageraient un substitut : collision).
    v = unicodedata.normalize("NFC", value.strip())
    if etype in ("URL", "REPO"):
        # Les identifiants d'accès d'une URL (`https://user:jeton@hôte/…`) sont
        # des SECRETS : ils ne doivent pas entrer dans la clé du coffre, sinon
        # la colonne `real` les rend restaurables (D4).
        v = _strip_userinfo(v)
        # `https://hôte` et `https://hôte/` désignent la même ressource. Les
        # garder distincts créait deux enregistrements pour un substitut
        # identique — conflit d'unicité que la régénération ne pouvait pas
        # résoudre, puisque l'hôte fictif est stable.
        # `https://hôte/` en compte trois, `hôte/` (sans schéma) un seul : le
        # second tombait à côté et recevait sa propre entrée de coffre, liée au
        # substitut DÉJÀ pris par l'hôte — collision insoluble, donc 503 en
        # pleine session pour un simple « visite example.com/ ».
        if v.endswith("/") and v.count("/") in (1, 3):
            v = v[:-1]
    low = v.lower()

    def canon(key: str, kind: str, **attrs: str) -> Canonical:
        return Canonical(key=key, kind=kind, attrs=attrs, normalized=v)

    if etype == "IP_ADDRESS":
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            # Une notation CIDR (`10.1.2.0/24`) n'est pas une adresse, et elle
            # tombait donc dans le générique : elle sortait sous un MOT
            # (`glacier-vault10`), ni adresse ni réseau. Le modèle voyait alors
            # des hôtes dans un réseau fictif et un « sous-réseau » qui n'en
            # était pas un — et concluait, à juste titre, à une incohérence.
            # Trouvé en session réelle, pas par une revue.
            if "/" in v:
                try:
                    reseau = ipaddress.ip_network(v, strict=False)
                except ValueError:
                    return canon(f"generic:{low}", "generic")
                return canon(f"cidr:{reseau}", "cidr",
                             subnet=str(reseau.network_address),
                             prefixlen=str(reseau.prefixlen),
                             private=str(est_privee(reseau)),
                             v=str(reseau.version))
            return canon(f"generic:{low}", "generic")
        prefixe = 24 if ip.version == 4 else 64
        subnet = str(ipaddress.ip_network(f"{ip}/{prefixe}", strict=False).network_address)
        return canon(f"ip:{ip}", "ip", subnet=subnet,
                     private=str(est_privee(ip)), v=str(ip.version))

    if etype == "EMAIL_ADDRESS" and "@" in v:
        local, _, domain = v.partition("@")
        return canon(f"email:{low}", "email",
                     actor="service" if _looks_like_service(local) else "human",
                     domain=domain.lower(), local=local.lower(), env=env_of(local) or "")

    if etype in ("URL", "REPO") and (repo := _extract_repo(v, etype)):
        org, name = repo
        return canon(f"repo:{org}/{name}", "repo",
                     org=org, name=name, env=env_of(name) or "")

    if etype == "URL" and _is_bare_host(v):
        # Une URL réduite à un nom d'hôte EST un hôte : sans cela le même
        # serveur recevait deux identités fictives selon le type détecté.
        short, zone = split_host(low)
        return canon(f"host:{short}", "host", zone=zone,
                     internal=str(is_internal_host(low)),
                     env=env_of(short) or env_of(zone) or "")

    if etype in ("HOSTNAME", "FQDN", "CERT_CN", "HEX_HOSTNAME"):
        short, zone = split_host(low)
        return canon(f"host:{short}", "host", zone=zone,
                     internal=str(is_internal_host(low)),
                     env=env_of(short) or env_of(zone) or "")

    if etype == "CONTAINER_IMAGE":
        return canon(f"image:{low}", "image", env=env_of(low) or "")

    return canon(f"{etype.lower()}:{low}", "generic", env=env_of(low) or "",
                 actor="service" if _looks_like_service(low) else "")


_SERVICE_PREFIXES = ("svc-", "sa-", "srv-", "service-", "system:", "bot-", "ci-")
_SERVICE_SUFFIXES = ("-svc", "-sa", "-bot", "-agent", "-runner", "-job", "-operator")


#: Schémas d'URI qui ne portent pas d'AUTORITÉ : ce qui suit le deux-points est
#: une adresse, une charge ou une référence — pas un hôte, et l'arobase d'un
#: `mailto:` sépare le local du domaine, ce n'est pas un userinfo.
SCHEMAS_SANS_AUTORITE = frozenset({"mailto", "data", "tel", "urn", "sms"})


def _strip_userinfo(url: str) -> str:
    """Retire `user:motdepasse@` d'une URL, en gardant le reste intact."""
    scheme, sep, rest = url.partition("://")
    if not sep and url.partition(":")[0].lower() in SCHEMAS_SANS_AUTORITE:
        # `mailto:alice@hôte` : l'arobase sépare le local du domaine. Le
        # traiter comme un userinfo faisait disparaître le schéma ET le local,
        # et la valeur devenait un simple nom d'hôte (D1).
        return url
    if not sep:
        # Forme SSH `user:jeton@hôte:chemin`, sans schéma. Elle porte les mêmes
        # identifiants qu'une URL HTTPS et n'a pas plus à entrer dans la clé du
        # coffre (D4). L'userinfo ne contient ni `/`, ni `?`, ni `#`.
        userinfo, at, hostport = url.rpartition("@")
        if at and userinfo and not any(c in userinfo for c in "/?#"):
            return hostport
        return url
    authority, slash, tail = rest.partition("/")
    _userinfo, at, hostport = authority.rpartition("@")
    if not at:
        return url
    return f"{scheme}://{hostport}{slash}{tail}"


def _looks_like_service(name: str) -> bool:
    n = name.lower()
    return n.startswith(_SERVICE_PREFIXES) or n.endswith(_SERVICE_SUFFIXES)


def _repo_authority(value: str) -> str:
    """Hôte d'une URL de dépôt, quelle que soit sa forme (HTTPS, SSH, scp)."""
    reste = value.split("://", 1)[1] if "://" in value else value
    reste = reste.split("@", 1)[-1]  # userinfo éventuel
    return re.split(r"[:/]", reste, maxsplit=1)[0].lower()


def _extract_repo(value: str, etype: str = "REPO") -> tuple[str, str] | None:
    """org/nom depuis une URL HTTPS, une forme SSH ou une forme courte."""
    v = value.strip()
    # L'hôte est comparé en ENTIER : une simple sous-chaîne faisait passer
    # `attacker-github.com/org/repo` pour du GitHub, et le substitut affichait
    # alors `github.com` — une confiance fabriquée, que le modèle peut lire.
    autorite = _repo_authority(v)
    for host in REPO_HOSTS:
        if autorite != host and not autorite.endswith(f".{host}"):
            continue
        # `autorite` est en minuscules, `v` non : sans `re.I`, `GitHub.com`
        # ne correspond à rien et `re.split` renvoie une liste d'UN élément —
        # `IndexError`, que le proxy ne rattrape pas (500). Et une URL réduite
        # à l'hôte (`https://github.com`) n'a rien à découper du tout.
        morceaux = re.split(rf"{re.escape(autorite)}[:/]", v, maxsplit=1, flags=re.I)
        if len(morceaux) < 2:
            return None
        tail = morceaux[1]
        # `https://github.com:443/org/dépôt` : le port n'est pas l'organisation.
        tail = re.sub(r"^\d+/", "", tail)
        tail = tail.split("?")[0].split("#")[0]
        if tail.endswith(".git"):
            tail = tail[:-4]
        parts = [p for p in tail.strip("/").split("/") if p]
        if len(parts) >= 2:
            return parts[0].lower(), parts[1].lower()
        return None
    # Forme courte `org/dépôt`. Elle ne vaut QUE pour un type REPO : sur une
    # URL, `example.com/api` et `admin/config` sont des chemins relatifs, et
    # les traiter en dépôt fabriquait une URL `github.com/…` que le modèle
    # pouvait croire clonable.
    if etype != "REPO":
        return None
    m = re.fullmatch(r"([A-Za-z0-9][\w.-]*)/([A-Za-z0-9][\w.-]*)", v)
    if m:
        return m.group(1).lower(), m.group(2).lower()
    return None
