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
from typing import Any, Callable
from urllib.parse import unquote_plus

from ..modes import (ARBITRAGE_BLOQUANT, CHEMINS_COMPLET, CHEMINS_UTILISATEUR,
                     CHEMINS_UTILISATEUR_PROJET, DOMAINES_RESERVES)
from ..policy import Decision, Policy
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
from . import dates
from .classes import DataClass, class_of
from .lexicon import (
    EXTERNAL_TLDS,
    RESERVED_TLDS,
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

#: Types que le MOTEUR découpe lui-même dans une valeur composite. Ils vont au
#: coffre — la restauration en dépend, un segment absent du coffre rend un
#: chemin composé illisible — mais ils ne posent PAS de question d'arbitrage :
#: l'unité que l'opérateur reconnaît est le chemin, pas chacun de ses segments.
#: Mesuré : router les segments par le coffre a fait passer la file de 205 à
#: 267 questions, dont 62 pour des morceaux que personne n'a jamais désignés.
#: Granulaire là où ça sert (restaurer), grossier là où ça coûte (arbitrer).
TYPES_COMPOSITION: frozenset[str] = frozenset({"PATH_SEGMENT"})

#: Un port est un NOMBRE (RFC 3986), borné à 65535 (RFC 6335). Tout le reste
#: après le « : » d'une autorité d'URL est un identifiant, et doit être
#: substitué. La LONGUEUR ne suffit pas : `:99999` a cinq chiffres et n'est
#: pas un port.
_PORT_RE = re.compile(r"\d{1,5}")


def _porte_un_port(texte: str) -> bool:
    return _PORT_RE.fullmatch(texte) is not None and int(texte) < 65536

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
                 is_public: Callable[[str], bool] | None = None,
                 policy: "Policy | None" = None,
                 projet: str | None = None):
        self.vault = vault
        self.scope_key = scope_key
        #: Chemin ABSOLU du projet, tel que le lanceur l'exporte
        #: (`ANONPROXY_PROJECT`). Le nom du dépôt s'y lit ; le déduire d'une
        #: POSITION (`/home/<user>/<projet>`) était un pari sur la disposition
        #: des répertoires de l'opérateur, et il faisait sortir le nom du dépôt
        #: en clair dès que le projet n'était pas directement sous le home.
        self._projet = [p for p in projet.split("/") if p] if projet else None
        #: Politique de confidentialité. Absente = tout est anonymisé, ce qui
        #: est aussi le défaut quand elle est présente : elle ne peut
        #: qu'OUVRIR, jamais fermer davantage.
        self.policy = policy
        #: Prédicat « cette sous-partie est publique » — l'allowlist §6. Le
        #: détecteur l'applique aux entités entières ; il faut la consulter à
        #: nouveau ici, sur les COMPOSANTS d'une valeur composite (tag d'image,
        #: segment d'URL) que le détecteur n'a jamais vus isolément.
        # Deux arguments : la valeur ET son type. Une entrée d'allowlist peut
        # se limiter à des types (`code` public en FILE_PATH, jamais en
        # HOSTNAME) — sans le type, elle ne s'applique pas.
        self.is_public = is_public or (lambda _value, _etype=None: False)
        self._master = master_key.encode() if isinstance(master_key, str) else master_key
        # Sel de portée : deux portées ne dérivent jamais le même substitut.
        self._salt = hmac.new(self._master, scope_key.encode(), hashlib.sha256).digest()
        #: Attributs partagés déjà résolus : (type interne, réel) → substitut.
        self._shared: dict[tuple[str, str], str] = {}

    #: Racines de l'arborescence Unix. Liste FERMÉE, et c'est elle qui rend
    #: la règle sûre : ces répertoires existent sur toutes les machines, donc
    #: les laisser en clair ne dit rien de celle-ci. Une racine hors liste
    #: retombe sur la substitution complète — on ne devine pas une forme qu'on
    #: n'a pas modélisée.
    _RACINES = frozenset({
        "home", "Users", "root", "usr", "etc", "var", "opt", "tmp", "srv",
        "mnt", "media", "proc", "sys", "dev", "bin", "sbin", "lib", "lib64",
        "boot", "run", "Applications", "Library", "System", "private",
    })

    #: Racines sous lesquelles le segment suivant est un NOM D'UTILISATEUR.
    _RACINES_HOME = frozenset({"home", "Users"})

    def _fake_path(self, v: str, attempt: int) -> str:
        """Un chemin est un CONTENANT : on ne substitue que ce qui identifie.

        Trois natures dans un même chemin, que le masquage en bloc confondait :
        une racine standard, présente partout et qui ne dit rien ; un nom
        d'utilisateur, qui désigne une personne ; un chemin relatif et un nom
        de fichier, qui désignent un contenu dont le modèle a BESOIN pour
        travailler.

        Le masquage total n'était pas « plus sûr », il était plus bruyant — et
        ce bruit a un coût mesuré : au round 7, un agent a épuisé ses tours à
        chercher un fichier dont on avait maquillé le nom.
        """
        parts = [p for p in v.split("/") if p]
        if not parts:  # « / », « // » : la racine n'a rien à masquer
            return v
        absolu = v.startswith("/")

        def masque(i: int, p: str) -> str:
            # Par le COFFRE, jamais par un tirage direct. Tiré hors du coffre,
            # le substitut n'entrait dans aucune table : il restait LIBRE
            # (une autre valeur réelle pouvait l'obtenir, D6) et surtout il
            # n'était pas RESTAURABLE — seul le chemin entier l'était. Dès que
            # le modèle composait un autre fichier du même dossier, `Read`
            # recevait un chemin fictif et échouait, pendant qu'un `cat` sur la
            # chaîne déjà vue fonctionnait. Mesuré en session réelle ; et
            # `unresolved` restait à zéro, un substitut jamais enregistré étant
            # invisible au compteur comme à la restauration.
            return self.substitute_value("PATH_SEGMENT", p)

        garder = self._segments_gardes(parts, absolu)
        sortie = [p if i in garder else masque(i, p) for i, p in enumerate(parts)]
        out = "/".join(sortie)
        return f"/{out}" if absolu else out

    def _segments_gardes(self, parts: list[str], absolu: bool) -> set[int]:
        """Les indices que le substitut conserve — la règle, en un seul endroit.

        Elle sert deux fois : ici pour construire le substitut, et en amont
        pour reconnaître un chemin qui ne porte AUCUN identifiant (`/home`,
        `/usr`). Sans ce second usage, le substitut serait égal au réel et la
        garde d'injectivité le refuserait, 64 fois, avant de rendre un 503.
        """
        reglage = (self.policy.reglage("chemins") if self.policy is not None
                   else CHEMINS_UTILISATEUR_PROJET)
        # Un chemin RELATIF ne dit pas où commence le projet, et une racine
        # inconnue n'est pas une racine : dans les deux cas on ferme.
        # Un segment `.` ou `..` non plus : il DÉCALE les positions, et comme il
        # se substitue à lui-même (aucun caractère alphanumérique), le chemin
        # reconstruit devenait identique à l'original — les 64 tentatives
        # tombaient en identité et la garde rendait le chemin ENTIER, nom
        # d'utilisateur et de dépôt compris, sans entrée de coffre. Un chemin
        # absolu qui en porte est ANORMAL : c'est le moment de fermer.
        if reglage == CHEMINS_COMPLET or not absolu \
                or parts[0] not in self._RACINES \
                or any(p in (".", "..") for p in parts):
            return set()
        if parts[0] in self._RACINES_HOME:
            # `/home` reste · l'utilisateur sort · le nom du PROJET sort selon
            # le réglage · tout le reste est du contenu, et reste.
            sortent = {1} if len(parts) > 1 else set()
            if reglage != CHEMINS_UTILISATEUR:
                # Le nom du dépôt est à SA place dans le chemin du projet, pas
                # à l'indice 2 : `/home/jo/lab/ai/anonproxy-demo` laissait
                # `anonproxy-demo` en clair — or un dépôt porte souvent le nom
                # du client — et masquait `lab` pour rien.
                if self._projet is not None \
                        and len(parts) >= len(self._projet) \
                        and parts[:len(self._projet) - 1] == self._projet[:-1]:
                    sortent.add(len(self._projet) - 1)
                elif self._projet is None:
                    # Projet inconnu : on ne sait pas où est le dépôt, et ne
                    # rien masquer le laisserait sortir dans la disposition la
                    # plus courante. Le pari de position reste donc en repli —
                    # masquer un répertoire de trop est visible et réparable,
                    # laisser sortir un nom de dépôt ne l'est pas.
                    sortent.add(2)
            return set(range(len(parts))) - sortent
        # Une racine système sans utilisateur : la racine reste, le reste est
        # substitué. `/etc/acme-vpn.conf` peut nommer une entreprise, et rien
        # ici ne permet de trancher — donc on ne tranche pas.
        return {0}

    def _chemin_sans_identifiant(self, value: str) -> bool:
        """Ce chemin n'a-t-il rien à masquer ? (`/home`, `/usr`, `/`)"""
        parts = [p for p in value.strip().split("/") if p]
        if not parts:
            return True
        return len(self._segments_gardes(parts, value.strip().startswith("/"))) \
            == len(parts)

    #: Espaces de noms que la RFC 2606 réserve à la documentation : ils
    #: n'appartiennent à personne, par spécification.
    _RESERVES_RFC2606 = (".example", ".test", ".invalid", ".localhost",
                         "example.com", "example.net", "example.org")

    def _tlds_externes(self, zone: str = "") -> tuple[str, ...]:
        """Espace des TLD fictifs — arbitrage d'opérateur, pas constante.

        `tld_reels` privilégie la plausibilité (D1) et accepte qu'un domaine
        fictif puisse exister vraiment ; `reserves` garantit l'inverse au prix
        de la plausibilité. Aucun des deux n'est « le bon » : c'est pourquoi
        c'est un réglage.

        Sauf quand le réel est DÉJÀ réservé : là il n'y a rien à peser.
        `acmecorp.example` sortait en `parnell-alpine.co`, donc un domaine
        garanti à personne devenait un domaine qui peut appartenir à quelqu'un
        — la substitution rendait la valeur MOINS sûre qu'elle ne l'était.
        Rester dans le réservé ne coûte aucune plausibilité, puisque l'original
        était réservé : c'est un attribut déjà présent qu'on préserve, comme
        « interne vs externe » et la co-appartenance /24 (§3.4).
        """
        bas = zone.lower()
        if any(bas == r.lstrip(".") or bas.endswith(r)
               for r in self._RESERVES_RFC2606):
            return RESERVED_TLDS
        if self.policy is not None \
                and self.policy.reglage("domaines_fictifs") == DOMAINES_RESERVES:
            return RESERVED_TLDS
        return EXTERNAL_TLDS

    # -- dérivation --------------------------------------------------------- #

    def _digest(self, *parts: str) -> bytes:
        msg = "\x1f".join(parts).encode("utf-8")
        return hmac.new(self._salt, msg, hashlib.sha256).digest()

    def _idx(self, *parts: str) -> int:
        return int.from_bytes(self._digest(*parts)[:8], "big")

    #: Bornes du décalage des dates, en jours. Assez grand pour qu'un
    #: recoupement avec un calendrier réel ne retrouve pas la date d'origine ;
    #: assez petit pour que l'année reste plausible — un incident daté de 2043
    #: se remarque autant qu'un `[DATE_1]`.
    _DECALAGE_MIN, _DECALAGE_MAX = 200, 1200

    #: Vocabulaire de voie : il n'identifie personne, et le substituer rendrait
    #: une chaîne qui n'est plus une adresse — la première clause de
    #: l'invariant cassée pour satisfaire la seconde.
    _VOIES = frozenset({
        "rue", "avenue", "boulevard", "impasse", "place", "chemin", "allée",
        "allee", "quai", "cours", "route", "voie", "square", "villa",
        "street", "road", "lane", "drive", "court", "way", "close",
    })
    #: Articles et particules : ils n'identifient personne, et les substituer
    #: donne `rue riley Ollie` là où `rue des Ollie` se lit comme une adresse.
    _PARTICULES = frozenset({"de", "des", "du", "la", "le", "les", "d",
                             "of", "the", "at"})

    def _fake_address(self, value: str, attempt: int) -> str:
        """Réécrit l'adresse en gardant sa FORME et rien de ce qui situe.

        Les chiffres partent aussi, code postal compris : garder le code garde
        la localité, et la localité est précisément ce sur quoi un recoupement
        se fait. Ce qui reste — `rue`, `street` — ne désigne personne.
        """
        morceaux = re.split(r"([^\w'’-]+)", value)
        rendu = []
        for i, morceau in enumerate(morceaux):
            nu = morceau.strip()
            if not nu or not re.search(r"\w", nu):
                rendu.append(morceau)          # séparateurs : conservés
            elif nu.lower() in self._VOIES or nu.lower() in self._PARTICULES:
                rendu.append(morceau)          # vocabulaire commun : conservé
            elif nu.isdigit():
                # Même longueur : un code postal à cinq chiffres reste un code
                # postal, un numéro de rue reste un numéro de rue.
                tire = self._idx("adresse-n", value, str(i), str(attempt))
                rendu.append(str(tire % (10 ** len(nu))).zfill(len(nu)))
            elif re.fullmatch(r"\d+\w+", nu):  # `221B`
                tire = self._idx("adresse-bis", value, str(i), str(attempt))
                rendu.append(f"{tire % 900 + 1}{nu[-1]}")
            else:
                mot = pick(IDENTITY_WORDS,
                           self._idx("adresse-m", value, str(i), str(attempt)))
                rendu.append(mot.capitalize() if nu[:1].isupper() else mot)
        return "".join(rendu)

    def _fake_date(self, value: str) -> str | None:
        """Décale la date d'UNE constante par portée.

        La constante ne dépend PAS de la valeur : c'est ce qui préserve les
        intervalles, donc la chronologie d'un incident. Une translation est
        aussi injective par construction — deux dates distinctes ne peuvent
        pas tomber sur la même.

        Prix assumé, à compter parmi les attributs préservés : l'ÉCART entre
        deux dates survit à la substitution.
        """
        etendue = self._DECALAGE_MAX - self._DECALAGE_MIN
        jours = self._DECALAGE_MIN + self._idx("date-shift") % etendue
        return dates.shift(value, jours)

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

        if etype in ("FILE_PATH", "USER_PATH") and self._chemin_sans_identifiant(value):
            return value  # « / », « /home », « /usr » : rien à masquer

        if not _HAS_ALNUM.search(value):
            # Un fragment sans caractère alphanumérique (un saut de ligne resté
            # d'un arbitrage de recouvrement) n'a rien à masquer. L'enregistrer
            # créait une correspondance vers la chaîne VIDE : si le modèle citait
            # ce substitut, il disparaissait de la réponse de l'opérateur.
            return value

        if klass is DataClass.SECRET:
            # D4 : dérivé, jamais stocké, donc jamais restauré au retour.
            return self._secret_reference(etype, value)

        # APRÈS la classe SECRET, et c'est essentiel : `default`, `localhost`,
        # `admin` sont parmi les mots de passe faibles les plus répandus. Tester
        # l'allowlist d'abord les laissait sortir verbatim ET sautait la
        # référence qu'exige D4. Un secret reste un secret même quand son
        # contenu coïncide avec un jeton public.
        if self.is_public(value, etype):
            # Entrée EXACTE de l'allowlist : une décision prise token par token,
            # donc valable partout (round 9). Le détecteur l'écarte déjà ; on le
            # refait ici pour qu'un détecteur en retard sur le fichier ne fasse
            # pas TOMBER la requête. Le cas qui l'impose : `10.0.0.0/8` et
            # `198.18.0.0/15` sont les plages mêmes où l'on tire les substituts,
            # ils ne peuvent donc que se substituer à eux-mêmes — 64 tentatives
            # refusées par la garde d'identité, puis 503.
            return value

        # Clé d'unicité = forme CANONIQUE, pas (type, texte brut). Sans cela,
        # un même hôte vu comme HOSTNAME puis FQDN puis CERT_CN — ou écrit
        # `DB-01.acme.internal` puis `db-01.acme.internal` — recevait plusieurs
        # identités fictives : le modèle croyait voir plusieurs machines.
        canon = canonicalize(etype, value)
        key_type = f"canon:{canon.kind}:{etype}" if canon.kind == "generic" else f"canon:{canon.kind}"
        stored = _display_value(canon, value)

        # POLITIQUE — le seul endroit d'où une valeur réelle peut ressortir.
        # Consultée APRÈS la canonicalisation, pour qu'une décision prise sur
        # `DB-01.acme.internal` vaille aussi pour `db-01.acme.internal`, et
        # APRÈS la branche SECRET, qui n'est jamais révélable (D4).
        source = None
        if self.policy is not None:
            decision, source = self.policy.decide(etype, klass.value, stored)
            if decision is Decision.REVELER:
                return value

        known = self.vault.get_surrogate(self.scope_key, key_type, stored)
        if known is not None:
            return known

        identites = 0
        for attempt in range(MAX_ATTEMPTS):
            candidate = self._candidate(etype, value, attempt, canon)
            if candidate == value or candidate == stored:
                identites += 1
                continue  # jamais l'identité : ce serait une fuite silencieuse
            try:
                surrogate = self.vault.bind(self.scope_key, key_type, stored, candidate)
            except SurrogateConflict:
                continue
            if self.policy is not None and source is None \
                    and etype not in TYPES_COMPOSITION:
                # Aucune règle ne couvrait cette valeur. Elle est DÉJÀ
                # substituée : le substitut est alloué avant l'arbitrage, ce
                # qui permet à la question de ne porter que lui — l'opérateur
                # remonte à la valeur par le coffre, la file ne révèle rien.
                self.policy.en_attente(etype, klass.value, stored, surrogate)
                if self.policy.reglage("arbitrage") == ARBITRAGE_BLOQUANT:
                    # Mode consciencieux : la requête ATTEND. À l'échéance, la
                    # valeur reste anonymisée — un délai dépassé ne vaut jamais
                    # un consentement.
                    if self.policy.attendre_decision(
                            etype, klass.value, stored) is Decision.REVELER:
                        return value
            return surrogate

        if identites == MAX_ATTEMPTS:
            # Le générateur a rendu la valeur elle-même à CHAQUE tentative. Ce
            # n'est pas une malchance : il n'y a rien à substituer, toutes les
            # parties identifiantes sont publiques (`http://127.0.0.1/`,
            # `https://claude.ai`, `10.0.0.0/8`). Refuser faisait tomber la
            # requête ENTIÈRE en 503 — mesuré par `tests/phase3_e2e.sh`, deux
            # fois, sur deux types différents.
            # La distinction est ce qui rend la règle sûre : une seule collision
            # RÉELLE (`SurrogateConflict`) suffit à retomber dans le refus. On
            # ne rend jamais une valeur au motif qu'un substitut était pris.
            return value

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
        if canon.kind == "cidr":
            return self._fake_cidr(canon, attempt)
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

    def _fake_cidr(self, canon: Canonical, attempt: int = 0) -> str:
        """Réseau fictif — le MÊME que celui des adresses qu'il contient.

        La co-appartenance /24 est un attribut préservé (réponse §3.4) : le
        sous-réseau fictif est déjà alloué et partagé par les hôtes du réseau
        réel. Le rendre ici, plutôt que d'en tirer un nouveau, est ce qui rend
        la notation LISIBLE — sans quoi le modèle voit des adresses dans un
        réseau et une déclaration de réseau qui ne les contient pas.
        """
        subnet, prefixlen = canon.attrs["subnet"], int(canon.attrs["prefixlen"])
        v = canon.attrs["v"]

        if prefixlen == (64 if v == "6" else 24):
            # La longueur À LAQUELLE la co-appartenance est définie : le réseau
            # fictif EST celui des hôtes, déjà alloué comme attribut partagé.
            faux = self._fake_ip(
                Canonical(key=f"ip:{subnet}", kind="ip", normalized=subnet,
                          attrs={"subnet": subnet,
                                 "private": canon.attrs["private"], "v": v}),
                "")
            return str(ipaddress.ip_network(f"{faux}/{prefixlen}", strict=False))

        # Toute autre longueur : dériver du /24 partagé n'a aucun sens, puisque
        # le masque écarte justement les octets qui distinguent deux réseaux.
        # Deux réseaux réels distincts retombaient sur le même substitut, et un
        # réseau qui EST la base de l'espace fictif se substituait à lui-même —
        # 64 tentatives identiques, donc 503. On tire un INDICE de sous-réseau :
        # l'appartenance à l'espace réservé est garantie par construction, et la
        # tentative fait varier le tirage.
        return str(self._reseau_fictif(
            v, canon.attrs["private"] == "True", prefixlen,
            f"{subnet}/{prefixlen}", attempt))

    #: Espaces où un réseau fictif peut vivre, par (version, privé). Tous
    #: RÉSERVÉS : jamais alloués, jamais routés — un substitut ne doit jamais
    #: désigner la machine d'un tiers (round 18). Le dernier de chaque liste est
    #: le repli pour un préfixe trop court pour les précédents : `240.0.0.0/4`
    #: (RFC 1112, classe E) accepte tout à partir de /4, au prix d'une
    #: plausibilité moindre — un réseau plus large qu'un /15 public est rare.
    _ESPACES_FICTIFS: dict[tuple[str, bool], tuple[str, ...]] = {
        ("4", True): ("10.0.0.0/8", "240.0.0.0/4"),
        ("4", False): ("198.18.0.0/15", "240.0.0.0/4"),
        ("6", True): ("fc00::/7", "0100::/8"),
        ("6", False): ("2001:db8::/32", "0100::/8"),
    }

    def _reseau_fictif(self, v: str, private: bool, prefixlen: int,
                       reel: str, attempt: int) -> str:
        vraie = ipaddress.ip_network(reel, strict=False)
        # À sa PROPRE longueur de préfixe, un espace réservé ne contient qu'un
        # seul réseau : le premier réseau réel le prend, et le second ne peut
        # plus que collisionner — soixante-quatre fois, donc 503. Un espace à un
        # seul emplacement n'est pas un espace.
        espaces = [sup for sup in
                   map(ipaddress.ip_network, self._ESPACES_FICTIFS[(v, private)])
                   if prefixlen > sup.prefixlen]
        # La TENTATIVE fait tourner l'espace, pas seulement le tirage à
        # l'intérieur. Rendre toujours le premier espace valide plafonnait la
        # capacité à celle de cet espace : `198.18.0.0/15` ne contient que DEUX
        # /16, donc le troisième réseau public de cette taille tombait en 503
        # alors que le repli `240.0.0.0/4` en offrait quatre mille.
        for decalage in range(len(espaces)):
            sup = espaces[(attempt + decalage) % len(espaces)]
            index = int(self._digest("cidr", reel, str(attempt)).hex()[:32], 16)
            index %= 1 << (prefixlen - sup.prefixlen)
            adresse = int(sup.network_address) + (
                index << (sup.max_prefixlen - prefixlen))
            reseau = ipaddress.ip_network((adresse, prefixlen))
            if v == "4" and str(reseau).startswith("255."):
                # `gen4` écarte déjà 255.x pour les HÔTES : un réseau qui
                # contient `255.255.255.255` ferait émettre une diffusion
                # limitée à un outil qui prend le substitut au mot. Même
                # intention, l'autre moitié de l'implémentation.
                continue
            if reseau == vraie:
                # Un espace fictif ne peut pas se représenter LUI-MÊME : à sa
                # propre longueur de préfixe il n'offre qu'un réseau, et c'est
                # la valeur réelle. On passe à l'espace suivant plutôt que
                # d'épuiser les 64 tentatives de l'appelant — même arbitrage
                # qu'un `sha256:` sans corps au round 16 : une valeur dégénérée
                # ne doit pas faire tomber la requête.
                continue
            return str(reseau)
        # Aucun espace réservé n'admet un préfixe aussi COURT — `128.0.0.0/1`,
        # `2000::/3`, `fd00::/7`. Refuser ici tuait la session pour une valeur
        # qui ne désigne ni machine ni plan d'adressage : un réseau de cette
        # largeur est une constante de routage. On le rend, et la garde
        # d'identité de `substitute_value` en fait le même constat que pour
        # `10.0.0.0/8`. Sortir de l'espace réservé, en revanche, nommerait le
        # réseau d'un tiers — ce n'est jamais l'option.
        return str(vraie)

    def _fake_ip(self, canon: Canonical, tweak: str) -> str:
        subnet = canon.attrs["subnet"]

        private = canon.attrs["private"] == "True"

        if canon.attrs["v"] == "6":
            def gen6(t: int) -> str:
                h = self._digest("ipv6-net", subnet, str(t)).hex()
                if private:
                    return f"fd{h[:2]}:{h[2:6]}:{h[6:10]}:{h[10:14]}"
                # Une adresse PUBLIQUE devenait une ULA `fd…` : l'attribut
                # « interne vs externe » (§3.4) ne survivait pas en IPv6, alors
                # qu'il tenait en IPv4. Espace de documentation, comme son
                # équivalent v4 — plausible et non routé.
                return f"2001:db8:{h[:4]}:{h[4:8]}"
            prefix = self._alloc_shared(self._SUBNET6, subnet, gen6)
            # 64 bits d'hôte (4 groupes) : un /64 dense épuiserait un espace
            # de 16 bits par collisions bien avant MAX_ATTEMPTS.
            h = self._digest("ipv6-host", canon.key, tweak).hex()
            return f"{prefix}:{h[:4]}:{h[4:8]}:{h[8:12]}:{h[12:16]}"

        def gen4(t: int) -> str:
            n = self._idx("ipv4-net", subnet, str(t))
            if private:  # plages privées plausibles (10/8, 172.16/12)
                if n % 2:
                    return f"10.{n % 256}.{(n >> 8) % 256}.0"
                return f"172.{16 + (n % 16)}.{(n >> 8) % 256}.0"
            # Espace public FICTIF. Les blocs de documentation ne font qu'UN
            # /24 chacun : faire varier leur troisième octet pour obtenir
            # plusieurs réseaux SORTAIT de la plage réservée et tombait sur de
            # l'espace réellement alloué et routable — `198.51.32.0/24`
            # appartient à quelqu'un. Un substitut ne doit jamais désigner la
            # machine d'un tiers : si le modèle propose une commande qui le
            # vise, elle part chez lui.
            # Trouvé par le MODÈLE en session, l'annonce activée.
            #
            # RFC 2544 (`198.18.0.0/15`) est réservé aux bancs d'essai : jamais
            # routé, jamais alloué, et il offre 512 réseaux /24.
            if t < 32:
                return f"198.{18 + ((n >> 8) % 2)}.{n % 256}.0"
            # 512 réseaux suffisent à une session ordinaire, pas à un log
            # d'analytics ni à l'audit d'un pare-feu : la 513e adresse publique
            # d'un /24 distinct épuisait l'espace et tuait la session. Repli sur
            # `240.0.0.0/4` (RFC 1112, classe E), réservé lui aussi, et qui
            # offre un million de /24. Les 32 premières tentatives restent
            # inchangées : un coffre existant garde ses allocations.
            # 255.x est écarté : `255.255.255.255` est la diffusion limitée.
            return f"{240 + (n % 15)}.{(n >> 8) % 256}.{(n >> 16) % 256}.0"

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
            tld = pick(self._tlds_externes(zone), self._idx("tld", zone))
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
            # Le DERNIER `@` sépare l'autorité : découper sur le PREMIER
            # rendait l'identifiant en position d'hôte, donc en clair —
            # `git@alice-payments-svc:JETON@github.com:org/dépôt.git` sortait
            # en `git@alice-payments-svc:…`, alors que la canonicalisation
            # avait pourtant bien retiré ces identifiants de la clé de coffre.
            # Un identifiant est un SECRET, il ne se recopie jamais (D4).
            host = v.rsplit("@", 1)[1].split(":", 1)[0]
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

    #: Plages de FICTION réservées par les régulateurs : elles ne sonnent chez
    #: personne. Chaque entrée : (préfixes réels reconnus, préfixe fictif). La
    #: correspondance se fait sur la chaîne de CHIFFRES, longueur comprise —
    #: `06…` en France est un mobile, `+33 6…` le même numéro depuis l'étranger.
    #: Même invariant qu'au round 18 pour les adresses : un substitut ne doit
    #: JAMAIS désigner une entité du monde réel. Un numéro tiré au hasard sonne
    #: chez quelqu'un, et c'est le modèle qui proposera de l'appeler.
    _PLAGES_FICTIVES: tuple[tuple[tuple[str, ...], str], ...] = (
        (("336", "337"), "3363998"),          # France mobile, international
        (("06", "07"), "063998"),             # France mobile, national
        (("331", "332", "333", "334", "335", "339"), "3319900"),  # France fixe
        (("01", "02", "03", "04", "05", "09"), "019900"),
        # Ofcom ne réserve que `020 7946 0xxx` : le zéro fait PARTIE du
        # préfixe. Le laisser libre rendait `020 7946 5123`, un vrai numéro
        # londonien — la même erreur qu'un troisième octet varié au round 18.
        (("4420",), "442079460"),             # Londres, numéros de drame Ofcom
        (("447",), "447700900"),              # Royaume-Uni mobile, 07700 900xxx
        # NANP : c'est la LIGNE `01xx` de l'indicatif d'abonné `555` qui est
        # réservée — et elle l'est pour N'IMPORTE QUEL indicatif régional
        # (FCC). Figer `555` comme régional ne laissait que DEUX chiffres
        # libres, donc cent numéros : un export de CRM ou un journal d'appels
        # tuait la session au 98e. L'indicatif régional varie donc aussi, ce
        # qui porte l'espace à quatre-vingt mille.
        (("1",), "1{aaa}55501"),              # +1 AAA 555 01xx
    )

    #: Repli INTERNATIONAL : `210` n'est attribué à aucun pays (E.164), donc le
    #: numéro ne joint personne où que ce soit. Composer `555…` derrière le
    #: `+` fabriquait au contraire un indicatif RÉEL — `+49 …` sortait en
    #: `+55 …`, c'est-à-dire le Brésil : un substitut désignait le téléphone
    #: d'un tiers, la faute même que le round 18 a corrigée sur les adresses.
    #: Prix assumé : le numéro n'est plus plausible pour son pays (D1). Entre
    #: les deux, l'invariant tranche.
    _PLAGE_INTERNATIONALE = "210"

    #: Repli NATIONAL : `555 555 01xx` est réservé à la fiction dans le plan
    #: NANP. RÉSIDU ASSUMÉ — hors NANP, un numéro national sans plan reconnu
    #: n'a aucune plage prouvablement injoignable qui préserve sa longueur.
    _PLAGE_PAR_DEFAUT = "{aaa}55501"

    def _fake_phone(self, value: str, attempt: int) -> str:
        """Numéro fictif de MÊME forme : longueur, indicatif, ponctuation.

        Sans branche dédiée, `PHONE_NUMBER` tombait dans le générique et
        sortait sous un MOT (`planner-tundra06`) : le modèle ne pouvait ni le
        reconnaître, ni le formater, ni raisonner dessus.
        """
        chiffres = re.sub(r"\D", "", value)
        if not chiffres:
            return value

        def rendu(gabarit: str) -> str:
            if "{aaa}" not in gabarit:
                return gabarit
            # Un indicatif régional NANP commence par 2 à 9 (format NXX).
            return gabarit.format(
                aaa=200 + self._idx("phone-nanp", chiffres, str(attempt)) % 800)

        prefixe = None
        for debuts, gabarit in self._PLAGES_FICTIVES:
            # Le gabarit est formaté AVANT la comparaison de longueur : mesurer
            # `1{aaa}55501` comptait les accolades, donc le plan NANP paraissait
            # trop long et tombait sur le repli international — un numéro
            # américain sortait sous un indicatif non attribué.
            if chiffres.startswith(debuts) and len(candidat := rendu(gabarit)) \
                    < len(chiffres):
                prefixe = candidat
                break
        if prefixe is None:
            prefixe = rendu(
                self._PLAGE_INTERNATIONALE if value.lstrip().startswith("+")
                else self._PLAGE_PAR_DEFAUT)

        reste = len(chiffres) - len(prefixe)
        if reste <= 0:
            # Plus court que sa propre plage de fiction : un poste, un code
            # court. Tronquer le préfixe donnait une valeur CONSTANTE — aucune
            # variation par tentative, donc deux postes distincts se
            # disputaient un substitut et le second tombait en 503.
            # Ces numéros-là ne joignent personne depuis l'extérieur : ils
            # n'ont pas de plage de fiction à respecter, seulement une forme.
            if attempt == 0:
                faux = prefixe[:len(chiffres)]
            else:
                court = self._idx("phone-court", chiffres, str(attempt))
                faux = f"{court % (10 ** len(chiffres)):0{len(chiffres)}d}"
        else:
            corps = self._idx("phone", chiffres, str(attempt)) % (10 ** reste)
            faux = f"{prefixe}{corps:0{reste}d}"

        suite = iter(faux)
        return "".join(next(suite) if c.isdigit() else c for c in value)

    #: Un IBAN : deux lettres de pays, deux chiffres de contrôle, puis le BBAN.
    _IBAN_RE = re.compile(r"([A-Z]{2})(\d{2})([0-9A-Z]{6,30})")

    #: Positions du BBAN mises à ZÉRO — l'identifiant d'établissement. Un IBAN
    #: valide tiré au hasard désigne le compte de QUELQU'UN ; à zéro, la banque
    #: n'est allouée nulle part. Même arbitrage que la RFC 2544 pour les
    #: adresses et les plages de fiction pour les numéros (round 18).
    _IBAN_BANQUE = 5

    def _fake_iban(self, value: str, attempt: int) -> str | None:
        """IBAN fictif de MÊME forme, à clé de contrôle VALIDE.

        Sans branche dédiée, `IBAN_CODE` tombait dans le générique et sortait
        sous un MOT (`registry-kestrel76`) ou sous une empreinte hexadécimale.
        Le modèle l'a signalé deux fois en session réelle : « un IBAN français
        fait 27 caractères, celui-ci en compte 30 ». Il avait raison, et une
        forme cassée coûte double — le modèle commente le gabarit au lieu de
        travailler, et il reformate la valeur, ce qui fait échouer la
        restauration par correspondance exacte.

        Rend None si la valeur n'a pas la forme d'un IBAN : le détecteur se
        trompe parfois, et fabriquer un faux IBAN à partir d'autre chose serait
        pire que de laisser le générique faire son travail.
        """
        brut = re.sub(r"[^0-9A-Za-z]", "", value).upper()
        forme = self._IBAN_RE.fullmatch(brut)
        if forme is None:
            return None
        pays, _, bban = forme.groups()

        h = self._digest("iban", brut, str(attempt)).hex().upper()
        corps = []
        for i, c in enumerate(bban):
            chiffre = int(h[i % len(h)], 16)
            if i < self._IBAN_BANQUE:
                # Les deux classes : un BBAN britannique porte son code banque
                # en LETTRES (`BUKB`). N'en neutraliser qu'une laissait un code
                # d'établissement réel — `ZZZZ` n'est attribué à aucun BIC.
                corps.append("0" if c.isdigit() else "Z")
            elif c.isdigit():
                corps.append(str(chiffre % 10))
            else:
                corps.append(chr(ord("A") + chiffre % 26))
        bban = "".join(corps)

        # ISO 13616 : les quatre premiers caractères passent à la fin, chaque
        # lettre vaut sa position + 9, et le tout doit valoir 1 modulo 97.
        reste = int("".join(str(int(c, 36)) for c in f"{bban}{pays}00")) % 97
        faux = f"{pays}{98 - reste:02d}{bban}"

        # Le GABARIT d'origine est rendu tel quel : espaces aux mêmes places.
        suite = iter(faux)
        return "".join(next(suite) if c.isalnum() else c for c in value)

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
        if _PLAIN_TAG_RE.fullmatch(tag) or self.is_public(tag, "CONTAINER_IMAGE"):
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

        if etype == "PHONE_NUMBER":
            return self._fake_phone(value, attempt)

        if etype == "IBAN_CODE" and (faux := self._fake_iban(value, attempt)):
            return faux

        if etype in ("FILE_PATH", "USER_PATH"):
            return self._fake_path(v, attempt)

        if etype == "DATE" and (faux := self._fake_date(value)) is not None:
            return faux

        if etype == "ADDRESS":
            return self._fake_address(v, attempt)

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
            # MÊME règle que pour la forme `host:port` plus bas : ce qui suit
            # le « : » n'est un port que si c'est un nombre. Ne corriger qu'une
            # des deux branches laissait `http://[fd00::1]:db-master.acme.
            # internal/` sortir avec son identifiant intact.
            # RFC 3986 : après le « ] », SEUL `:port` est valide. Tout le reste
            # est un identifiant en fin d'autorité. Ne traiter que la forme
            # `:port` laissait `[fd00::1]tenant-acme-nda/` sortir intact — la
            # même correction, appliquée à une branche sur deux, deux tours de
            # suite.
            if sep and after:
                if after.startswith(":"):
                    if not _porte_un_port(after[1:]):
                        after = f":{self.substitute_value('HOSTNAME', after[1:])}"
                else:
                    after = self.substitute_value("HOSTNAME", after)
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
        # Ce qui suit le « : » n'est un PORT que si c'est un nombre (RFC 3986).
        # Il était recopié verbatim quoi qu'il porte, donc
        # `https://hote.reel:tenant-acme-nda` sortait avec son identifiant
        # intact — sans entrée de coffre ni substitut non résolu pour le
        # signaler. Et si l'hôte est PUBLIC, l'URL entière devenait sa propre
        # identité, donc rendue telle quelle : la fuite la plus silencieuse que
        # le système sache produire.
        if sep and not _porte_un_port(port):
            port = self.substitute_value("HOSTNAME", port)
        return (f"{prefix}{self.substitute_value('HOSTNAME', host)}",
                f":{port}" if sep else "")

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
