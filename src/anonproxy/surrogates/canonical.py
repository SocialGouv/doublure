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

_REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")


@dataclass(frozen=True)
class Canonical:
    """Forme canonique d'une valeur : clé stable + attributs à préserver."""

    key: str                     # identité canonique (entrée du HMAC)
    kind: str                    # host | ip | email | repo | image | generic | …
    attrs: dict[str, str]        # env, internal, subnet, actor…


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


def canonicalize(etype: str, value: str) -> Canonical:
    # NFC : « café » composé et décomposé désignent la même entité et doivent
    # produire le même substitut, sinon deux identités fictives coexistent.
    # Attention : ce n'est PAS une normalisation d'homoglyphes — `аcme` en
    # cyrillique reste une entité distincte, et doit le rester (sinon deux
    # réels différents partageraient un substitut : collision).
    v = unicodedata.normalize("NFC", value.strip())
    low = v.lower()

    if etype == "IP_ADDRESS":
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return Canonical(key=f"generic:{low}", kind="generic", attrs={})
        if ip.version == 4:
            subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
            return Canonical(
                key=f"ip:{ip}",
                kind="ip",
                attrs={"subnet": subnet, "private": str(ip.is_private), "v": "4"},
            )
        subnet = str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address)
        return Canonical(
            key=f"ip:{ip}", kind="ip",
            attrs={"subnet": subnet, "private": str(ip.is_private), "v": "6"},
        )

    if etype in ("EMAIL_ADDRESS",) and "@" in v:
        local, _, domain = v.partition("@")
        actor = "service" if _looks_like_service(local) else "human"
        return Canonical(
            key=f"email:{low}", kind="email",
            attrs={"actor": actor, "domain": domain.lower(),
                   "local": local.lower(), "env": env_of(local) or ""},
        )

    if etype in ("URL", "REPO") and (repo := _extract_repo(v)):
        org, name = repo
        return Canonical(
            key=f"repo:{org}/{name}", kind="repo",
            attrs={"org": org, "name": name, "env": env_of(name) or ""},
        )

    if etype in ("HOSTNAME", "FQDN", "CERT_CN", "HEX_HOSTNAME"):
        short, zone = split_host(low)
        return Canonical(
            key=f"host:{short}", kind="host",
            attrs={"zone": zone, "internal": str(is_internal_host(low)),
                   "env": env_of(short) or env_of(zone) or ""},
        )

    if etype == "CONTAINER_IMAGE":
        return Canonical(key=f"image:{low}", kind="image", attrs={"env": env_of(low) or ""})

    return Canonical(
        key=f"{etype.lower()}:{low}", kind="generic",
        attrs={"env": env_of(low) or "", "actor": "service" if _looks_like_service(low) else ""},
    )


_SERVICE_PREFIXES = ("svc-", "sa-", "srv-", "service-", "system:", "bot-", "ci-")
_SERVICE_SUFFIXES = ("-svc", "-sa", "-bot", "-agent", "-runner", "-job", "-operator")


def _looks_like_service(name: str) -> bool:
    n = name.lower()
    return n.startswith(_SERVICE_PREFIXES) or n.endswith(_SERVICE_SUFFIXES)


def _extract_repo(value: str) -> tuple[str, str] | None:
    """org/nom depuis une URL HTTPS, une forme SSH ou une forme courte."""
    v = value.strip()
    for host in _REPO_HOSTS:
        if f"{host}/" in v or f"{host}:" in v:
            tail = re.split(rf"{re.escape(host)}[:/]", v, maxsplit=1)[1]
            tail = tail.split("?")[0].split("#")[0]
            if tail.endswith(".git"):
                tail = tail[:-4]
            parts = [p for p in tail.strip("/").split("/") if p]
            if len(parts) >= 2:
                return parts[0].lower(), parts[1].lower()
            return None
    m = re.fullmatch(r"([A-Za-z0-9][\w.-]*)/([A-Za-z0-9][\w.-]*)", v)
    if m:
        return m.group(1).lower(), m.group(2).lower()
    return None
