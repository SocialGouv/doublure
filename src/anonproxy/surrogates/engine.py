"""Moteur de substituts plausibles (plan §5 Phase 2).

Principe : ``HMAC(sel_de_portée, valeur_canonique)`` → index dans un lexique.
Le sel dérive de la portée (`scope_key`), ce qui rend le substitut stable
DANS la portée et incorrélable entre portées (réponse §3.1 : par projet par
défaut, configurable).

Contraintes tenues ici :

- **Injectivité** (D6) : le coffre porte l'unicité ; en cas de conflit on
  régénère avec un compteur de tentative, jamais on n'écrase.
- **Morphologie préservée** : ``svc-payments-prod`` → ``svc-billing-prod``
  (même forme, même environnement).
- **Co-appartenance** : même /24 réel → même /24 fictif ; même zone DNS →
  même zone fictive ; même org de dépôt → même org fictive.
- **Secrets** (D4) : dérivés SANS passer par le coffre, donc jamais restaurés.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import unicodedata
from typing import Any

from ..vault import SurrogateConflict, Vault
from .canonical import Canonical, canonicalize, is_internal_host, split_host
from .classes import DataClass, class_of
from .lexicon import (
    EXTERNAL_TLDS,
    IDENTITY_WORDS,
    ORG_WORDS,
    REGISTRY_WORDS,
    SERVICE_ACCOUNT_WORDS,
    SERVICE_WORDS,
    pick,
)
from .overlap import resolve_overlaps

MAX_ATTEMPTS = 64

#: Tags d'image manifestement publics : versions et canaux standard.
_PLAIN_TAG_RE = re.compile(
    r"v?\d+(\.\d+)*(-(alpha|beta|rc|pre)\.?\d*)?|latest|stable|edge|slim|"
    r"alpine|bookworm|bullseye|nonroot|distroless",
    re.I,
)


class SurrogateCollisionError(RuntimeError):
    """Espace de substituts épuisé pour cette valeur : fail-closed (D5/D6)."""


def _display_value(canon: Canonical, value: str) -> str:
    """Forme mémorisée dans le coffre — c'est elle qui sera restaurée.

    Normalisée pour que les variantes d'écriture d'une même entité partagent
    un enregistrement : DNS et e-mails sont insensibles à la casse, un point
    final est significatif pour le résolveur mais pas pour l'identité.
    """
    v = unicodedata.normalize("NFC", value.strip())
    if canon.kind in ("host", "email", "repo", "image"):
        return v.rstrip(".").lower()
    return v


class SurrogateEngine:
    """Génère et mémorise les substituts d'une portée.

    ``scope_key`` : ``project:<nom>`` (défaut), ``session:<id>``,
    ``tenant:<nom>`` ou ``global`` — cf. réponse §3.1.
    """

    def __init__(self, vault: Vault, master_key: str, scope_key: str):
        self.vault = vault
        self.scope_key = scope_key
        self._master = master_key.encode() if isinstance(master_key, str) else master_key
        # Sel de portée : deux portées ne dérivent jamais le même substitut.
        self._salt = hmac.new(self._master, scope_key.encode(), hashlib.sha256).digest()

    # -- dérivation --------------------------------------------------------- #

    def _digest(self, *parts: str) -> bytes:
        msg = "\x1f".join(parts).encode("utf-8")
        return hmac.new(self._salt, msg, hashlib.sha256).digest()

    def _idx(self, *parts: str) -> int:
        return int.from_bytes(self._digest(*parts)[:8], "big")

    # -- API ---------------------------------------------------------------- #

    def substitute_value(self, etype: str, value: str) -> str:
        """Substitut pour une valeur détectée. Déterministe dans la portée."""
        if etype.startswith("_"):
            # Types réservés aux attributs partagés : un span forgé sur
            # `_SUBNET_V4` empoisonnerait l'allocation et ferait échouer toutes
            # les IP du réseau concerné.
            raise ValueError(f"type d'entité réservé au moteur : {etype!r}")
        klass = class_of(etype)

        if klass is DataClass.PUBLIC:
            return value  # allowlist : laissé en clair

        if etype in ("FILE_PATH", "USER_PATH") and not [p for p in value.split("/") if p]:
            return value  # « / », « // » : la racine ne porte aucun identifiant

        if klass is DataClass.SECRET:
            # D4 : dérivé, jamais stocké, donc jamais restauré au retour.
            return self._secret_reference(etype, value)

        # Clé d'unicité = forme CANONIQUE, pas (type, texte brut). Sans cela,
        # un même hôte vu comme HOSTNAME puis FQDN puis CERT_CN — ou écrit
        # `DB-01.acme.internal` puis `db-01.acme.internal` — recevait plusieurs
        # identités fictives : le modèle croyait voir plusieurs machines.
        canon = canonicalize(etype, value)
        key_type = f"canon:{canon.kind}:{etype}" if canon.kind == "generic" else f"canon:{canon.kind}"
        stored = _display_value(canon, value)

        known = self.vault.get_surrogate(self.scope_key, key_type, stored)
        if known is not None:
            return known

        for attempt in range(MAX_ATTEMPTS):
            candidate = self._candidate(etype, value, attempt)
            if candidate == value or candidate == stored:
                continue  # jamais l'identité : ce serait une fuite silencieuse
            try:
                return self.vault.bind(self.scope_key, key_type, stored, candidate)
            except SurrogateConflict:
                continue
        raise SurrogateCollisionError(
            f"aucun substitut libre après {MAX_ATTEMPTS} tentatives "
            f"(type={etype!r}, portée={self.scope_key!r})"
        )

    def surrogates_view(self) -> dict[str, str]:
        """Table substitut → réel (sens entrant). Ne contient aucun secret."""
        return self.vault.view(self.scope_key)

    def transform(self, text: str, spans: list[dict[str, Any]]) -> str:
        """Applique les substitutions sur ``text`` à partir des spans détectés.

        Les recouvrements sont arbitrés par la table de priorité, puis le
        remplacement se fait par découpe (offsets), de droite à gauche pour
        que les offsets restants restent valides.
        """
        for span in spans:
            start, end = span.get("start"), span.get("end")
            if not isinstance(start, int) or not isinstance(end, int) \
                    or start < 0 or end > len(text) or start >= end:
                # Un span incohérent glisse silencieusement à travers le
                # découpage Python et peut DUPLIQUER la valeur réelle dans la
                # sortie. Fail-closed : on refuse plutôt que d'émettre.
                raise ValueError(
                    f"span invalide {start}:{end} pour un texte de {len(text)} "
                    f"caractères (type={span.get('type')!r})"
                )

        kept = resolve_overlaps(spans)
        out = text
        for span in sorted(kept, key=lambda s: s["start"], reverse=True):
            real = text[span["start"]:span["end"]]
            fake = self.substitute_value(span["type"], real)
            out = out[:span["start"]] + fake + out[span["end"]:]
        return out

    # -- génération par type ------------------------------------------------ #

    def _candidate(self, etype: str, value: str, attempt: int) -> str:
        canon = canonicalize(etype, value)
        tweak = "" if attempt == 0 else f"#{attempt}"
        if canon.kind == "ip":
            return self._fake_ip(canon, tweak)
        if canon.kind == "host":
            return self._fake_host(canon, value, attempt)
        if canon.kind == "email":
            return self._fake_email(canon, attempt)
        if canon.kind == "repo":
            return self._fake_repo(canon, value, attempt)
        if canon.kind == "image":
            return self._fake_image(canon, value, attempt)
        return self._fake_generic(etype, canon, value, attempt)

    # -- IP : co-appartenance /24 et classe privé/public --------------------- #

    #: Attributs PARTAGÉS entre entités (réseau, zone DNS, org de dépôt,
    #: registry). Ils sont alloués une fois pour toutes dans le coffre :
    #:  - même attribut réel  → toujours le même substitut (co-appartenance) ;
    #:  - attributs distincts → substituts distincts (unicité SQL, pas de
    #:    fusion de deux réseaux ou de deux organisations) ;
    #:  - la régénération d'une entité ne déplace JAMAIS son attribut partagé.
    _SUBNET4 = "_SUBNET_V4"
    _SUBNET6 = "_SUBNET_V6"
    _ZONE = "_ZONE"
    _REPO_ORG = "_REPO_ORG"
    _REGISTRY = "_REGISTRY"

    def _alloc_shared(self, etype: str, real: str, gen) -> str:
        """Alloue (ou retrouve) le substitut d'un attribut partagé."""
        known = self.vault.get_surrogate(self.scope_key, etype, real)
        if known is not None:
            return known
        for attempt in range(MAX_ATTEMPTS):
            candidate = gen(attempt)
            if candidate == real:
                # Un lexique fini finit par retomber sur la valeur réelle : la
                # zone `lamna.internal` ou le préfixe `172.22.96.0` se
                # substitueraient alors à eux-mêmes et partiraient EN CLAIR.
                continue
            try:
                return self.vault.bind(self.scope_key, etype, real, candidate)
            except SurrogateConflict:
                continue
        raise SurrogateCollisionError(
            f"aucun substitut libre pour l'attribut partagé {etype} après "
            f"{MAX_ATTEMPTS} tentatives ({real!r}, portée={self.scope_key!r})"
        )

    def _combo(self, ns: str, key: str, attempt: int, words: tuple[str, ...]) -> str:
        """Nom composé du lexique, avec escalade si l'index est déjà pris.

        Deux mots dès la PREMIÈRE tentative : un tirage sur un seul mot
        (~70 possibilités) collisionne dès la dizaine de valeurs, et c'est
        alors l'ordre d'arrivée qui décide qui obtient le mot — deux coffres
        neufs recevant les mêmes valeurs dans des ordres différents
        divergeaient. Deux mots portent l'espace à ~5 000, ce qui reste une
        forme parfaitement courante pour un service (`payment-gateway`).
        """
        a = pick(words, self._idx(f"{ns}-a", key, str(attempt)))
        b = pick(words, self._idx(f"{ns}-b", key, str(attempt)))
        if attempt < 16:
            return f"{a}-{b}"
        return f"{a}-{b}{self._idx(f'{ns}-n', key, str(attempt)) % 900 + 100}"

    def _fake_ip(self, canon: Canonical, tweak: str) -> str:
        subnet = canon.attrs["subnet"]

        if canon.attrs["v"] == "6":
            def gen6(t: int) -> str:
                h = self._digest("ipv6-net", subnet, str(t)).hex()
                return f"fd{h[:2]}:{h[2:6]}:{h[6:10]}:{h[10:14]}"
            prefix = self._alloc_shared(self._SUBNET6, subnet, gen6)
            # 64 bits d'hôte (4 groupes) : un /64 dense épuiserait un espace
            # de 16 bits par collisions bien avant MAX_ATTEMPTS.
            h = self._digest("ipv6-host", canon.key, tweak).hex()
            return f"{prefix}:{h[:4]}:{h[4:8]}:{h[8:12]}:{h[12:16]}"

        private = canon.attrs["private"] == "True"

        def gen4(t: int) -> str:
            n = self._idx("ipv4-net", subnet, str(t))
            if private:  # plages privées plausibles (10/8, 172.16/12)
                if n % 2:
                    return f"10.{n % 256}.{(n >> 8) % 256}.0"
                return f"172.{16 + (n % 16)}.{(n >> 8) % 256}.0"
            # espace public : blocs de documentation (plausibles, non routés)
            a, b, c = ((198, 51, 100), (203, 0, 113), (192, 0, 2))[n % 3]
            return f"{a}.{b}.{(c + (n >> 4)) % 256}.0"

        net = self._alloc_shared(self._SUBNET4, subnet, gen4)
        host_idx = self._idx("ipv4-host", canon.key, tweak) % 254 + 1
        a, b, c, _ = net.split(".")
        return f"{a}.{b}.{c}.{host_idx}"

    # -- hôtes : nom court + zone, interne/externe, env ---------------------- #

    def _zone_for(self, zone: str, internal: bool) -> str:
        """Zone DNS fictive — attribut PARTAGÉ, alloué une fois dans le coffre.

        Ne dépend jamais du numéro de tentative de l'entité appelante : deux
        hôtes de la même zone réelle gardent la même zone fictive, même si l'un
        des deux a dû être régénéré.
        """
        if not zone:
            return ""

        def gen(attempt: int) -> str:
            org = self._combo("zone", zone, attempt, ORG_WORDS)
            if internal:
                # conserve le suffixe interne réel (attribut « interne » préservé)
                for sfx in (".svc.cluster.local", ".cluster.local", ".internal",
                            ".local", ".lan", ".intra", ".corp", ".home.arpa"):
                    if zone.endswith(sfx) or zone.endswith(sfx.lstrip(".")):
                        return f"{org}{sfx}"
                return f"{org}.internal"
            tld = pick(EXTERNAL_TLDS, self._idx("tld", zone))
            return f"{org}.{tld}"

        return self._alloc_shared(self._ZONE, zone, gen)

    def _fake_short_host(self, short: str, env: str, attempt: int) -> str:
        word = self._combo("host", short, attempt, SERVICE_WORDS)
        # morphologie : on conserve la présence d'un index numérique et l'env
        m = re.search(r"(\d{1,4})", short)
        num = f"-{m.group(1)}" if m else ""
        env_part = f"-{env}" if env else ""
        return f"{word}{num}{env_part}"

    def _fake_host(self, canon: Canonical, value: str, attempt: int) -> str:
        short, zone = split_host(value.strip().lower())
        env = canon.attrs.get("env") or ""
        fake_short = self._fake_short_host(short, env, attempt)
        if not zone:
            return fake_short
        internal = canon.attrs.get("internal") == "True" or is_internal_host(value)
        return f"{fake_short}.{self._zone_for(zone, internal)}"

    # -- emails : humain vs service, domaine cohérent ------------------------ #

    def _fake_email(self, canon: Canonical, attempt: int) -> str:
        domain = canon.attrs["domain"]
        fake_domain = self._zone_for(domain, is_internal_host(domain))
        env = canon.attrs.get("env") or ""
        if canon.attrs["actor"] == "service":
            word = self._combo("svc-local", canon.key, attempt, SERVICE_WORDS)
            role = pick(SERVICE_ACCOUNT_WORDS, self._idx("svc-role", canon.key))
            env_part = f"-{env}" if env else ""
            return f"svc-{word}-{role}{env_part}@{fake_domain}"
        first = self._combo("id-first", canon.key, attempt, IDENTITY_WORDS)
        last = pick(IDENTITY_WORDS, self._idx("id-last", canon.key, str(attempt)))
        local = canon.attrs["local"]
        sep = "." if "." in local else ("_" if "_" in local else "")
        return f"{first}{sep}{last}@{fake_domain}" if sep else f"{first}{last}@{fake_domain}"

    # -- dépôts et images ---------------------------------------------------- #

    def _fake_org(self, org: str) -> str:
        """Organisation fictive — attribut PARTAGÉ (deux dépôts de la même org
        réelle restent dans la même org fictive, deux orgs ne fusionnent pas)."""
        return self._alloc_shared(
            self._REPO_ORG, org, lambda a: self._combo("repo-org", org, a, ORG_WORDS)
        )

    def _fake_repo_name(self, name: str, attempt: int) -> str:
        word = self._combo("repo-name", name, attempt, SERVICE_WORDS)
        suffix = ""
        for known in ("-api", "-service", "-svc", "-lib", "-cli", "-web", "-ui",
                      "-worker", "-operator", "-controller"):
            if name.endswith(known):
                suffix = known
                break
        return f"{word}{suffix}"

    def _fake_repo(self, canon: Canonical, value: str, attempt: int) -> str:
        org = self._fake_org(canon.attrs["org"])
        name = self._fake_repo_name(canon.attrs["name"], attempt)
        v = value.strip()
        if v.startswith("git@"):
            host = v.split("@", 1)[1].split(":", 1)[0]
            return f"git@{host}:{org}/{name}.git"
        for h in ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org"):
            if h in v:
                scheme = "https://" if v.startswith("http") else ""
                return f"{scheme}{h}/{org}/{name}"
        return f"{org}/{name}"

    def _fake_image(self, canon: Canonical, value: str, attempt: int) -> str:
        v = value.strip().lower()
        ref, _, tag = v.partition(":")
        parts = ref.split("/")
        if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0]):
            registry = parts[0]

            def gen_reg(a: int) -> str:
                reg = pick(REGISTRY_WORDS, self._idx("registry", registry, str(a)))
                return f"{reg}.{self._combo('registry-org', registry, a, ORG_WORDS)}.io"

            fake_registry = self._alloc_shared(self._REGISTRY, registry, gen_reg)
            rest = parts[1:]
        else:
            fake_registry = ""
            rest = parts
        fake_rest = "/".join(
            self._combo("image-part", f"{i}:{p}", attempt, SERVICE_WORDS)
            for i, p in enumerate(rest)
        )
        out = f"{fake_registry}/{fake_rest}" if fake_registry else fake_rest
        if not tag:
            return out
        # Un tag n'est PAS toujours une version : on y trouve des SHA de
        # commit, des noms de branche (`feat/PROJ-1234-…`), des logins, des
        # noms de clients. Seules les formes manifestement publiques passent.
        if _PLAIN_TAG_RE.fullmatch(tag):
            return f"{out}:{tag}"
        return f"{out}:{self._combo('image-tag', tag, attempt, SERVICE_WORDS)}"

    # -- générique : morphologie conservée ----------------------------------- #

    def _fake_generic(self, etype: str, canon: Canonical, value: str, attempt: int) -> str:
        v = value.strip()
        tweak = "" if attempt == 0 else f"#{attempt}"

        if etype in ("HASH", "COMMIT_SHA", "CERT_THUMBPRINT", "CERT_SERIAL"):
            digest = self._digest("hash", canon.key, tweak).hex()
            # Le préfixe d'algorithme (`sha256:`) est structurel : le perdre
            # empêche le modèle de savoir à quoi il a affaire.
            algo, sep, rest = v.partition(":")
            if sep and re.fullmatch(r"(?i)(sha\d+|md5|blake\d*|crc\d*)", algo):
                body = digest * ((len(rest) // 64) + 1)
                return f"{algo}:{body[:len(rest)]}"
            hexpart = re.sub(r"[^0-9a-fA-F]", "", v)
            n = len(hexpart) or 40
            body = (digest * ((n // 64) + 1))[:n]
            return v.replace(hexpart, body) if hexpart and hexpart in v else body

        if etype == "UUID":
            h = self._digest("uuid", canon.key, tweak).hex()
            # Version et variante recopiées : un v1 (horodaté) et un v5 (haché)
            # ne se raisonnent pas de la même façon.
            m = re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}"
                             r"-([0-9a-f])[0-9a-f]{3}-[0-9a-f]{12}", v, re.I)
            ver, variant = (m.group(1), m.group(2)) if m else ("4", "a")
            return f"{h[:8]}-{h[8:12]}-{ver}{h[13:16]}-{variant}{h[17:20]}-{h[20:32]}"

        if etype == "MAC_ADDRESS":
            h = self._digest("mac", canon.key, tweak).hex()
            octets = [h[i:i + 2] for i in range(0, 12, 2)]
            octets[0] = f"{(int(octets[0], 16) & 0xFE) | 0x02:02x}"  # unicast/local
            if "." in v:  # notation Cisco xxxx.xxxx.xxxx
                flat = "".join(octets)
                return ".".join(flat[i:i + 4] for i in range(0, 12, 4))
            sep = ":" if ":" in v else "-"
            return sep.join(octets)

        if etype in ("FILE_PATH", "USER_PATH"):
            parts = [p for p in v.split("/") if p]
            if not parts:  # « / », « // » : la racine n'a rien à masquer
                return v
            fake = [self._combo("path", f"{i}:{p}", attempt, SERVICE_WORDS)
                    for i, p in enumerate(parts)]
            out = "/".join(fake)
            return f"/{out}" if v.startswith("/") else out

        if etype == "PERSON":
            # Même nombre de mots : « Marie-Anne De La Fontaine » réduit à deux
            # jetons change la structure du texte et se remarque.
            words = v.split()
            first = self._combo("person-a", canon.key, attempt, IDENTITY_WORDS).capitalize()
            rest = [
                pick(IDENTITY_WORDS, self._idx("person-n", canon.key, str(i), tweak)).capitalize()
                for i in range(1, len(words))
            ]
            return " ".join([first, *rest])

        if etype in ("ORGANIZATION", "LOCATION"):
            word = self._combo("org", canon.key, attempt, ORG_WORDS)
            return word.capitalize() if v[:1].isupper() else word

        if etype == "URL":  # URL non-dépôt : hôte ET chemin substitués
            m = re.match(
                r"^(?P<scheme>[a-z][a-z0-9+.-]*://)?(?P<host>[^/?#]+)"
                r"(?P<path>[^?#]*)(?P<tail>[?#].*)?$", v, re.I,
            )
            if m:
                fake_host, port = self._fake_authority(m.group("host"), attempt)
                # Le chemin porte régulièrement des identifiants internes
                # (`/payments/api`, `/tenants/acme`) : le conserver tel quel
                # laissait fuir la moitié de l'URL.
                path = m.group("path")
                segments = [s for s in path.split("/") if s]
                fake_path = "".join(
                    "/" + self._combo("url-seg", f"{i}:{s}", attempt, SERVICE_WORDS)
                    for i, s in enumerate(segments)
                )
                if path.endswith("/") and segments:
                    fake_path += "/"
                tail = self._fake_query(m.group("tail") or "", attempt)
                return f"{m.group('scheme') or ''}{fake_host}{port}{fake_path}{tail}"

        # défaut : mot du lexique + morphologie (préfixe/suffixe/env/index)
        env = canon.attrs.get("env") or ""
        word = self._combo("generic", canon.key, attempt, SERVICE_WORDS)
        prefix = ""
        for p in ("svc-", "sa-", "srv-", "ci-", "bot-", "ns-", "app-", "team-"):
            if v.lower().startswith(p):
                prefix = p
                break
        m = re.search(r"(\d{1,6})", v)
        num = m.group(1) if m else ""
        pieces = [f"{prefix}{word}"]
        if num:
            pieces[0] = f"{prefix}{word}{num}"
        if env:
            pieces.append(env)
        return "-".join(pieces)

    def _fake_authority(self, authority: str, attempt: int) -> tuple[str, str]:
        """(hôte fictif, port) depuis la partie autorité d'une URL.

        Gère le littéral IPv6 entre crochets (`[fd00::1]:8080`), que le
        découpage naïf sur « : » transformait en hôte tronqué.
        """
        if authority.startswith("["):
            literal, sep, after = authority.partition("]")
            fake = self.substitute_value("IP_ADDRESS", literal[1:])
            return f"[{fake}]", (after if sep else "")
        host, sep, port = authority.partition(":")
        fake = self._fake_host(canonicalize("HOSTNAME", host), host, attempt)
        return fake, (f":{port}" if sep else "")

    def _fake_query(self, tail: str, attempt: int) -> str:
        """Substitue les VALEURS d'une query string, garde les noms de
        paramètres (ils font partie du contrat de l'API appelée)."""
        if not tail:
            return ""
        sep, rest = tail[0], tail[1:]
        parts = []
        for chunk in re.split(r"([&;])", rest):
            if chunk in ("&", ";"):
                parts.append(chunk)
                continue
            name, eq, value = chunk.partition("=")
            if eq and value:
                value = self._combo("url-arg", f"{name}:{value}", attempt, SERVICE_WORDS)
            parts.append(f"{name}{eq}{value}")
        return sep + "".join(parts)

    # -- secrets (D4) -------------------------------------------------------- #

    def _secret_reference(self, etype: str, value: str) -> str:
        """Substitut de secret : plausible (D1), déterministe, NON stocké.

        Jamais écrit dans le coffre : il ne peut donc pas être restauré au
        retour. Un secret est une référence résolue par le broker d'outils au
        moment de l'exécution, pas une valeur restaurée dans une commande
        générée par le modèle.
        """
        h = self._digest("secret", etype, value).hex()

        if etype == "JWT":
            def b64(seed: str, n: int) -> str:
                d = hashlib.sha256((h + seed).encode()).hexdigest()
                alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                return "".join(alphabet[int(d[i:i + 2], 16) % len(alphabet)]
                               for i in range(0, min(len(d), n * 2), 2))
            return f"{b64('h', 12)}.{b64('p', 24)}.{b64('s', 22)}"

        if etype in ("PRIVATE_KEY_PEM", "CERT_PEM", "CERT_REQUEST_PEM", "PGP_BLOCK"):
            m = re.search(r"-----BEGIN ([A-Z0-9 ]+)-----", value)
            label = m.group(1) if m else "PRIVATE KEY"
            body = "".join(
                hashlib.sha256((h + str(i)).encode()).hexdigest() for i in range(4)
            )
            lines = [body[i:i + 64] for i in range(0, len(body), 64)]
            return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----"

        # Préfixes de jetons connus : la structure reste plausible.
        for prefix in ("ghp_", "gho_", "ghs_", "github_pat_", "xoxb-", "xoxp-",
                       "sk-", "pk-", "AKIA", "ASIA", "glpat-", "npm_", "dop_v1_"):
            if value.startswith(prefix):
                n = max(len(value) - len(prefix), 16)
                alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                body = "".join(alphabet[int(h[i % 64:(i % 64) + 2] or "0", 16) % len(alphabet)]
                               for i in range(n))
                return prefix + body

        if etype == "PASSWORD_CONTEXT":
            # conserve le préfixe contextuel (« password: »), remplace la valeur
            m = re.match(r"(?P<label>.*?[:=]\s*)(?P<secret>\S+)$", value, re.S)
            if m:
                return m.group("label") + h[:20]
            return h[:20]

        return h[:max(16, min(len(value), 48))]
