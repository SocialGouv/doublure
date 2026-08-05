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
import re
import unicodedata
from typing import Any, Callable
from urllib.parse import unquote_plus

from ..vault import SurrogateConflict, Vault
from .canonical import (
    INTERNAL_SUFFIXES_LONGEST_FIRST,
    REPO_HOSTS,
    SCHEMAS_SANS_AUTORITE,

    Canonical,
    canonicalize,
    is_internal_host,
    split_host,
)
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

#: Une valeur sans caractère alphanumérique ne porte aucun identifiant.
_HAS_ALNUM = re.compile(r"\w", re.UNICODE)

#: Suffixes de dépôt conservés tels quels : ils qualifient le rôle, pas l'entité.
_REPO_SUFFIXES = ("-api", "-service", "-svc", "-lib", "-cli", "-web", "-ui",
                  "-worker", "-operator", "-controller")

#: Préfixes structurels conservés dans un identifiant générique.
_GENERIC_PREFIXES = ("svc-", "sa-", "srv-", "ci-", "bot-", "ns-", "app-", "team-")

#: Préfixes de jetons connus : la structure du secret reste plausible (D1).
_SECRET_PREFIXES = ("ghp_", "gho_", "ghs_", "github_pat_", "xoxb-", "xoxp-",
                    "sk-", "pk-", "AKIA", "ASIA", "glpat-", "npm_", "dop_v1_")

#: Alphabet des corps de jetons fictifs.
_TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

#: Tags d'image manifestement publics : versions et canaux standard.
_PLAIN_TAG_RE = re.compile(
    r"v?\d+(\.\d+)*(-(alpha|beta|rc|pre)\.?\d*)?|latest|stable|edge|slim|"
    r"alpine|bookworm|bullseye|nonroot|distroless",
    re.I,
)

#: Ce qui trahit un identifiant dans un NOM de paramètre de query : un nom
#: d'API n'a ni point (FQDN), ni arobase (e-mail), ni deux-points (IPv6).
_IDENT_EN_NOM_RE = re.compile(r"[.@:]")


class SurrogateCollisionError(RuntimeError):
    """Espace de substituts épuisé pour cette valeur : fail-closed (D5/D6)."""



def _display_value(canon: Canonical, value: str) -> str:
    """Forme mémorisée dans le coffre — c'est elle qui sera restaurée.

    Normalisée pour que les variantes d'écriture d'une même entité partagent
    un enregistrement : DNS et e-mails sont insensibles à la casse, un point
    final est significatif pour le résolveur mais pas pour l'identité.
    """
    v = canon.normalized  # déjà normalisée NFC et détourée par canonicalize()
    if canon.kind in ("host", "email", "repo", "image"):
        return v.rstrip(".").lower()
    return v


class SurrogateEngine:
    """Génère et mémorise les substituts d'une portée.

    ``scope_key`` : ``project:<nom>`` (défaut), ``session:<id>``,
    ``tenant:<nom>`` ou ``global`` — cf. réponse §3.1.
    """

    def __init__(self, vault: Vault, master_key: str, scope_key: str,
                 is_public: Callable[[str], bool] | None = None):
        self.vault = vault
        self.scope_key = scope_key
        #: Prédicat « cette sous-partie est publique » — l'allowlist §6. Le
        #: détecteur l'applique aux entités entières ; il faut la consulter à
        #: nouveau ici, sur les COMPOSANTS d'une valeur composite (tag d'image,
        #: segment d'URL) que le détecteur n'a jamais vus isolément.
        self.is_public = is_public or (lambda _value: False)
        self._master = master_key.encode() if isinstance(master_key, str) else master_key
        # Sel de portée : deux portées ne dérivent jamais le même substitut.
        self._salt = hmac.new(self._master, scope_key.encode(), hashlib.sha256).digest()
        #: Attributs partagés déjà résolus : (type interne, réel) → substitut.
        self._shared: dict[tuple[str, str], str] = {}

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

        if etype in ("FILE_PATH", "USER_PATH") and not [p for p in value.strip().split("/") if p]:
            return value  # « / », « // » : la racine ne porte aucun identifiant

        if not _HAS_ALNUM.search(value):
            # Un fragment sans caractère alphanumérique (un saut de ligne resté
            # d'un arbitrage de recouvrement) n'a rien à masquer. L'enregistrer
            # créait une correspondance vers la chaîne VIDE : si le modèle citait
            # ce substitut, il disparaissait de la réponse de l'opérateur.
            return value

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
            candidate = self._candidate(etype, value, attempt, canon)
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
            # Le type et le score alimentent l'arbitrage : un `None` ou une clé
            # absente y lève `TypeError`/`KeyError`, que le proxy ne rattrape
            # pas — 500 non structuré et session interrompue au lieu du
            # fail-closed prévu.
            if not isinstance(span.get("type"), str) \
                    or not isinstance(span.get("score", 0.0), (int, float)) \
                    or isinstance(span.get("score", 0.0), bool):
                raise ValueError(
                    f"span mal formé : type={span.get('type')!r} "
                    f"score={span.get('score')!r}"
                )

        kept = resolve_overlaps(spans)
        out = text
        for span in sorted(kept, key=lambda s: s["start"], reverse=True):
            real = text[span["start"]:span["end"]]
            fake = self.substitute_value(span["type"], real)
            out = out[:span["start"]] + fake + out[span["end"]:]
        return out

    # -- génération par type ------------------------------------------------ #

    def _candidate(self, etype: str, value: str, attempt: int,
                   canon: Canonical | None = None) -> str:
        # La forme canonique est calculée une fois par valeur et repassée à
        # chaque tentative : la recalculer coûtait une normalisation Unicode et
        # plusieurs regex par essai, jusqu'à 64 fois sur une collision.
        canon = canon if canon is not None else canonicalize(etype, value)
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
        """Alloue (ou retrouve) le substitut d'un attribut partagé.

        Un attribut partagé ne change jamais une fois lié : on le garde en
        mémoire, sinon chaque hôte d'une même zone rouvrait une requête SQL
        pour redemander la même réponse.
        """
        cached = self._shared.get((etype, real))
        if cached is not None:
            return cached
        known = self.vault.get_surrogate(self.scope_key, etype, real)
        if known is not None:
            self._shared[(etype, real)] = known
            return known
        for attempt in range(MAX_ATTEMPTS):
            candidate = gen(attempt)
            if candidate == real:
                # Un lexique fini finit par retomber sur la valeur réelle : la
                # zone `lamna.internal` ou le préfixe `172.22.96.0` se
                # substitueraient alors à eux-mêmes et partiraient EN CLAIR.
                continue
            try:
                bound = self.vault.bind(self.scope_key, etype, real, candidate)
                self._shared[(etype, real)] = bound
                return bound
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
        # Un mot du lexique peut coïncider avec un mot de la valeur réelle
        # (`gateway-021` → `gateway-registry-021`) : le substitut garderait
        # alors un morceau reconnaissable du réel. On décale jusqu'à un tirage
        # qui n'en reprend aucun.
        present = set(re.findall(r"[a-z]{3,}", key.lower()))
        for shift in range(8):
            seed = str(attempt) if shift == 0 else f"{attempt}~{shift}"
            a = pick(words, self._idx(f"{ns}-a", key, seed))
            b = pick(words, self._idx(f"{ns}-b", key, seed))
            if a not in present and b not in present:
                break
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
                for sfx in INTERNAL_SUFFIXES_LONGEST_FIRST:
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
        return f"{fake_short}.{self._zone_for(zone, canon.attrs['internal'] == 'True')}"

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
        if "." in local:
            return f"{first}.{last}@{fake_domain}"
        if "_" in local:
            return f"{first}_{last}@{fake_domain}"
        return f"{first}{last}@{fake_domain}"

    # -- dépôts et images ---------------------------------------------------- #

    def _fake_org(self, org: str) -> str:
        """Organisation fictive — attribut PARTAGÉ (deux dépôts de la même org
        réelle restent dans la même org fictive, deux orgs ne fusionnent pas)."""
        return self._alloc_shared(
            self._REPO_ORG, org, lambda a: self._combo("repo-org", org, a, ORG_WORDS)
        )

    def _fake_sans_autorite(self, schema: str, reste: str, attempt: int) -> str:
        """Substitut d'un URI sans autorité, en gardant sa STRUCTURE."""
        if schema == "mailto":
            local, arobase, hote = reste.rpartition("@")
            if arobase:
                faux_hote, _ = self._fake_authority(hote, attempt)
                local_faux = self._combo("mail-local", local, attempt, IDENTITY_WORDS)
                return f"{local_faux}@{faux_hote}"
        if schema == "data":
            # `data:<media>;base64,<charge>` : le type de média est public, la
            # charge est du contenu. On remplace la charge, on garde la forme.
            entete, virgule, charge = reste.partition(",")
            if virgule:
                return f"{entete},{self._combo('data', charge, attempt, SERVICE_WORDS)}"
        return self._combo("uri", reste, attempt, SERVICE_WORDS)

    def _fake_repo_name(self, name: str, attempt: int) -> str:
        word = self._combo("repo-name", name, attempt, SERVICE_WORDS)
        suffix = next((s for s in _REPO_SUFFIXES if name.endswith(s)), "")
        return f"{word}{suffix}"

    def _fake_repo(self, canon: Canonical, value: str, attempt: int) -> str:
        org = self._fake_org(canon.attrs["org"])
        name = self._fake_repo_name(canon.attrs["name"], attempt)
        v = value.strip()
        if v.lower().startswith("git@"):
            host = v.split("@", 1)[1].split(":", 1)[0]
            return f"git@{host}:{org}/{name}.git"
        # La reconnaissance est insensible à la casse comme `_extract_repo`, et
        # le SCHÉMA d'origine est conservé : `https://GitHub.com/…` retombait
        # sinon sur la forme courte `org/dépôt`, que le modèle lit comme un
        # dépôt local et non comme une URL (D1).
        bas = v.lower()
        for h in REPO_HOSTS:
            if h in bas:
                scheme, sep, _ = v.partition("://")
                return f"{scheme}://{h}/{org}/{name}" if sep else f"{h}/{org}/{name}"
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
        # `is_public` est ici le prédicat des entrées EXACTES : une règle de
        # forme (`re:`) suppose un contexte que le tag n'a pas, et celle qui
        # reconnaît un nom de fichier laissait passer `tenant-nda-v1.tar`.
        if _PLAIN_TAG_RE.fullmatch(tag) or self.is_public(tag):
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
            # Registre FERMÉ, et non une forme libre : un préfixe inconnu
            # (`srv-billing-01:deadbeef`) serait CONSERVÉ, donc une fuite.
            # Mais le restreindre à `sha\d+` perdait `sha3-256`, `SHA-256`,
            # `blake2b`, `keccak256`, `xxh64` — et l'opérateur voyait un
            # hexadécimal nu, sans savoir à quoi il avait affaire (D1).
            if sep and re.fullmatch(
                    r"(?i)(sha-?\d+|sha3-\d+|shake\d+|md[45]|blake[23][bs]?"
                    r"|keccak\d*|crc\d*|xxh\d*|ripemd\d*|whirlpool|sm3)",
                    algo):
                # `sha256:` sans corps se re-substituerait à lui-même : la
                # garde `candidat == réel` rejette les 64 tentatives et la
                # requête tombe en 503. On donne un corps de longueur par
                # défaut plutôt que de refuser une valeur dégénérée.
                taille = len(rest) or 16
                body = digest * ((taille // 64) + 1)
                return f"{algo}:{body[:taille]}"
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

        # Un schéma sans `//` ne porte pas d'AUTORITÉ : le passer au
        # découpeur d'hôte rendait un nom d'hôte là où il y avait une adresse
        # mail, et le modèle ne pouvait plus raisonner dessus (D1).
        if etype == "URL":
            schema, sep, reste = v.partition(":")
            if sep and not reste.startswith("//") \
                    and schema.lower() in SCHEMAS_SANS_AUTORITE:
                return f"{schema}:{self._fake_sans_autorite(schema.lower(), reste, attempt)}"

        # Un dépôt AUTO-HÉBERGÉ (`https://code.acme.internal/team/outil`) n'a
        # pas d'hôte public reconnu : il retombait sur un simple MOT, que le
        # modèle ne peut ni cloner ni lire comme une URL. Il garde sa forme.
        if etype == "URL" or (etype == "REPO" and "://" in v):
            m = re.match(
                r"^(?P<scheme>[a-z][a-z0-9+.-]*://)?(?P<host>[^/?#]+)"
                r"(?P<path>[^?#]*)(?P<tail>[?#].*)?$", v, re.I,
            )
            if m:
                fake_host, port = self._fake_authority(m.group("host"), attempt)
                # Le chemin porte régulièrement des identifiants internes
                # (`/payments/api`, `/tenants/acme`) : le conserver tel quel
                # laissait fuir la moitié de l'URL.
                # `is_public` = entrées EXACTES seulement (cf. allowlist.py) :
                # une règle de forme laissait sortir `tenant-acme-nda.md` au
                # milieu d'une URL par ailleurs pseudonymisée.
                path = m.group("path")
                segments = [s for s in path.split("/") if s]
                fake_path = "".join(
                    "/" + (s if self.is_public(s)
                           else self._combo("url-seg", f"{i}:{s}", attempt, SERVICE_WORDS))
                    for i, s in enumerate(segments)
                )
                if path.endswith("/") and segments:
                    fake_path += "/"
                tail = self._fake_query(m.group("tail") or "", attempt)
                return f"{m.group('scheme') or ''}{fake_host}{port}{fake_path}{tail}"

        # défaut : mot du lexique + morphologie (préfixe/suffixe/env/index)
        env = canon.attrs.get("env") or ""
        word = self._combo("generic", canon.key, attempt, SERVICE_WORDS)
        prefix = next((p for p in _GENERIC_PREFIXES if v.lower().startswith(p)), "")
        m = re.search(r"(\d{1,6})", v)
        num = m.group(1) if m else ""
        pieces = [f"{prefix}{word}{num}"]
        if env:
            pieces.append(env)
        return "-".join(pieces)

    def _fake_authority(self, authority: str, attempt: int) -> tuple[str, str]:
        """(autorité fictive, port) depuis la partie autorité d'une URL.

        RFC 3986 : ``authority = [userinfo "@"] host [":" port]``. Découper
        naïvement sur le premier « : » prenait `user` pour l'hôte et recopiait
        `:motdepasse@hote.reel` tel quel dans le « port » — le mot de passe ET
        le domaine réel partaient en clair.
        """
        userinfo, at, hostport = authority.rpartition("@")
        prefix = ""
        if at:
            # L'identifiant et le mot de passe sont des SECRETS : dérivés, non
            # réversibles, jamais restaurés dans une commande générée (D4).
            user, sep, password = userinfo.partition(":")
            fake_user = self._combo("url-user", user, attempt, SERVICE_WORDS)
            # Le mot de passe SEUL : `_secret_reference` préserve le libellé qui
            # précède, et lui donner `user:password` republierait le nom réel.
            prefix = f"{fake_user}:{self._secret_reference('API_KEY', password)}@" \
                if sep else f"{fake_user}@"

        if hostport.startswith("["):  # littéral IPv6 : [fd00::1]:8443
            literal, sep, after = hostport.partition("]")
            fake = self.substitute_value("IP_ADDRESS", literal[1:])
            return f"{prefix}[{fake}]", (after if sep else "")

        if hostport.count(":") > 1:
            # IPv6 sans crochets : « host:port » n'a plus de sens, tout ce qui
            # suivait le premier « : » était recopié tel quel.
            return f"{prefix}{self.substitute_value('IP_ADDRESS', hostport)}", ""

        host, sep, port = hostport.partition(":")
        # `substitute_value` et non `_fake_host` : l'hôte d'une URL doit être
        # ENREGISTRÉ comme n'importe quel hôte. Le générer sans passer par le
        # coffre laissait son substitut libre, et un autre hôte réel pouvait
        # ensuite obtenir le même — la restauration désignait alors la mauvaise
        # machine (D6).
        return f"{prefix}{self.substitute_value('HOSTNAME', host)}", (f":{port}" if sep else "")

    def _fake_query(self, tail: str, attempt: int) -> str:
        """Substitue les VALEURS d'une query string ou d'un fragment.

        Les NOMS de paramètres sont conservés : ils font partie du contrat de
        l'API appelée. Le fragment (`#…`), lui, est une valeur entière — le
        traiter comme une paire `nom=valeur` le laissait intact, alors qu'il
        porte couramment un identifiant (`#tenant-acme-nda`).
        """
        if not tail:
            return ""
        sep, rest = tail[0], tail[1:]
        if sep == "#":
            return f"#{self._combo('url-frag', rest, attempt, SERVICE_WORDS)}" if rest else "#"

        # une query peut se terminer par un fragment : `?a=b#section`
        rest, hash_sep, frag = rest.partition("#")
        parts = []
        for chunk in re.split(r"([&;])", rest):
            if chunk in ("&", ";"):
                parts.append(chunk)
                continue
            name, eq, value = chunk.partition("=")
            if eq:
                # Le NOM d'un paramètre est un contrat d'API (`page`, `limit`,
                # `cursor`) : le substituer casserait le sens que le modèle
                # doit lire. Mais il porte parfois la donnée elle-même
                # (`?db-01.acme.internal=1`), et un nom d'API ne contient
                # jamais de point, d'arobase ni de deux-points.
                # Test sur la forme DÉCODÉE : `%2E` est un point, et un client
                # HTTP qui encode par défaut suffisait à contourner la règle.
                nom_sortant = (
                    self._combo("url-arg", name, attempt, SERVICE_WORDS)
                    if _IDENT_EN_NOM_RE.search(unquote_plus(name)) else name
                )
                if value:
                    # dérivé du nom RÉEL : le substitut du nom ne doit pas
                    # décaler celui de la valeur
                    value = self._combo("url-arg", f"{name}:{value}", attempt,
                                        SERVICE_WORDS)
                name = nom_sortant
            elif name:
                # paramètre sans valeur : c'est la donnée elle-même
                name = self._combo("url-arg", name, attempt, SERVICE_WORDS)
            parts.append(f"{name}{eq}{value}")
        out = sep + "".join(parts)
        return out + self._fake_query(f"#{frag}", attempt) if hash_sep else out

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
                return "".join(_TOKEN_ALPHABET[int(d[i:i + 2], 16) % len(_TOKEN_ALPHABET)]
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

        prefix = next((p for p in _SECRET_PREFIXES if value.startswith(p)), None)
        if prefix:
            n = max(len(value) - len(prefix), 16)
            body = "".join(
                _TOKEN_ALPHABET[int(h[i % 64:(i % 64) + 2] or "0", 16) % len(_TOKEN_ALPHABET)]
                for i in range(n)
            )
            return prefix + body

        if etype == "PASSWORD_CONTEXT":
            # Conserve le libellé contextuel (« password: ») et remplace TOUT
            # ce qui suit le PREMIER séparateur. Un `.*?[:=]\s*(\S+)$` se cale
            # sur le DERNIER mot de la chaîne : sur `oldpass=A newpass=B`, `A`
            # partait en clair dans le « libellé ».
            # Le libellé n'est repris que s'il est un simple mot : un span
            # SECRET gagne tous les arbitrages de recouvrement (D4), donc un
            # identifiant qui le précède n'a plus de span à lui.
            m = re.match(r"(?P<label>[^:=]*)(?P<sep>[:=]\s*)(?P<secret>\S.*)$",
                         value, re.S)
            if m and re.fullmatch(r"[A-Za-z][A-Za-z _-]*", m.group("label")):
                return m.group("label") + m.group("sep") + h[:20]
            return h[:20]

        return h[:max(16, min(len(value), 48))]
