"""
anthropic_walker.py
===================

Pseudonymisation bidirectionnelle pour l'API Messages d'Anthropic (/v1/messages),
conçue pour s'interposer entre Claude Code et api.anthropic.com via ANTHROPIC_BASE_URL.

Deux directions :

  SORTANT  (Claude Code -> Anthropic)  : valeurs reelles  -> substituts
  ENTRANT  (Anthropic -> Claude Code)  : substituts       -> valeurs reelles

Ce module ne fait QUE la traversee et la reecriture de la structure JSON/SSE.
La detection d'entites et la generation de substituts sont injectees via deux
callables (cf. `Substituter`). Branche AnonShield, Presidio ou ce que tu veux
derriere.

Invariants de conception
------------------------
1. Les blocs `thinking` / `redacted_thinking` sont OPAQUES. Ils portent une
   `signature` verifiee en amont : toute modification casse le tour suivant.
2. Les arguments d'outils ne sont JAMAIS resolus pendant le streaming. On
   accumule le `partial_json` jusqu'a `content_block_stop`, on parse, on valide,
   puis on resout atomiquement. Resoudre sur du JSON incomplet corrompt le
   payload et peut declencher une execution sur des arguments partiels.
3. Le texte, lui, est resolu en flux avec un tail buffer : un substitut peut
   etre coupe entre deux chunks SSE.
4. Fail-closed : un substitut absent de la table n'est jamais devine. Il reste
   en place et est signale dans `.unresolved`. L'outil echouera naturellement
   ("ressource inconnue"), ce qui est le comportement correct : le modele se
   corrige tout seul.
5. Determinisme : la substitution doit etre stable pour une meme session, sinon
   le prefixe de cache de prompt change a chaque tour.

Dependance recommandee en production : `pyahocorasick` pour `replace_all`.
L'implementation regex ci-dessous est correcte mais O(n * nb_substituts).
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

__all__ = [
    "Substituter",
    "walk_request",
    "walk_response",
    "SSERewriter",
    "UnresolvedSurrogate",
]


# --------------------------------------------------------------------------- #
# Regles de traversee
# --------------------------------------------------------------------------- #

#: Types de blocs de contenu a ne jamais toucher.
#: `thinking` et `redacted_thinking` sont signes cryptographiquement.
OPAQUE_BLOCK_TYPES: frozenset[str] = frozenset(
    {"thinking", "redacted_thinking"}
)

#: Cles dont la VALEUR ne doit jamais etre substituee. AUCUNE n'est recopiee
#: sans condition : chacune est gardee soit par sa POSITION (CONTRACT_KEYS),
#: soit par la FORME de sa valeur (SCALAR_SKIP_FORMS), soit par sa structure
#: (STRUCTURED_SKIP_KEYS), soit par le type de sa charge (`data`).
#: Recopiees sans condition, elles etaient FORGEABLES : un serveur MCP posait
#: `{"type": "text", "role": "<hote reel>"}` n'importe ou et la valeur sortait
#: verbatim, sans entree de coffre ni substitut non resolu pour le signaler.
#: `type`, `role`, `model`, `stop_reason` et `media_type` n'y figurent plus :
#: ils sont gardes par la FORME de leur valeur (SCALAR_SKIP_FORMS), testee
#: AVANT. `signature` non plus : sa seule position legitime est un bloc SIGNE,
#: rendu verbatim bien avant la boucle sur les cles — partout ailleurs, c'est
#: une valeur qu'un tiers ecrit.
SKIP_KEYS: frozenset[str] = frozenset(
    {
        "id",
        "tool_use_id",
        "name",
        "data",
        "cache_control",
    }
)

#: Cles de protocole dont la valeur appartient a un vocabulaire FERME ou a une
#: forme stricte. Elles ne restent verbatim que si leur valeur a cette forme —
#: un nom d'hote n'en a jamais l'air. La garde par forme vaut mieux que la
#: garde par position pour ces cles-la : `media_type` vit deux crans sous un
#: bloc, `type` partout, et les cadrer par position aurait casse l'API.
SCALAR_SKIP_FORMS: dict[str, re.Pattern[str]] = {
    # les types de bloc sont toujours en minuscules, sans tiret
    "type": re.compile(r"[a-z][a-z0-9_]*"),
    "role": re.compile(r"user|assistant|system"),
    "stop_reason": re.compile(
        r"end_turn|max_tokens|stop_sequence|tool_use|pause_turn|refusal|"
        r"model_context_window_exceeded"),
    "model": re.compile(r"(claude|gpt|gemini|llama|mistral|command|titan)"
                        r"[a-z0-9.\-]*", re.I),
    "media_type": re.compile(r"[\w.+-]+/[\w.+-]+"),
}

#: Cles de bloc dont la valeur est une STRUCTURE de protocole, pas du texte.
#: Meme regle que REQUEST_CONTROL_KEYS : la forme connue est recopiee, une cle
#: inattendue fait traverser le bloc entier. `cache_control` s'est enrichi de
#: `ttl` — dont l'API n'accepte que '5m' ou '1h' : le traverser le substituait
#: (400), le recopier en bloc laissait sortir une annotation posee par le client.
#: Chaque sous-cle admise avec la FORME de sa valeur. Un jeton de protocole
#: generique (`[A-Za-z0-9_+-]`) acceptait `{"type": "db-prod01"}` : un nom
#: d'hote court y passait verbatim. Toute forme inattendue fait traverser.
STRUCTURED_SKIP_KEYS: dict[str, dict[str, re.Pattern[str]]] = {
    "cache_control": {
        "type": re.compile(r"ephemeral|persistent"),
        "ttl": re.compile(r"\d+[smhd]"),
    },
}


def _forme_connue(value: Any, formes: dict[str, re.Pattern[str]]) -> bool:
    return isinstance(value, dict) and bool(value) and all(
        cle in formes and isinstance(val, str) and formes[cle].fullmatch(val)
        for cle, val in value.items()
    )


def _base64_texte(charge: str, fn: Callable[[str], str]) -> str:
    """Pseudonymise une charge base64 qui se decode en texte.

    Une charge qui ne se decode pas en UTF-8 est BINAIRE malgre son
    `media_type` : on la rend telle quelle, comme toute charge binaire — le
    detecteur ne saurait rien y lire, et la modifier la corromprait.
    """
    try:
        clair = base64.b64decode("".join(charge.split()),
                                 validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return charge
    return base64.b64encode(fn(clair).encode("utf-8")).decode("ascii")


def _traverse_hors_forme(value: Any, fn: Callable[[str], str],
                         formes: dict[str, re.Pattern[str]]) -> Any:
    """Traverse une valeur de forme INCONNUE, sans casser ce qui est connu.

    Une sous-cle dont la valeur a exactement la forme attendue reste verbatim :
    `cache_control.type` n'accepte que `ephemeral` ou `persistent`, et le
    substituer fait refuser la requete ENTIERE. Un champ ajoute demain a cote
    suffisait a declencher ce 400. Le reste est traverse en mode donnees.
    """
    if not isinstance(value, dict):
        return _walk(value, fn, in_user_data=True)
    return {
        cle: (val if (cle in formes and isinstance(val, str)
                      and formes[cle].fullmatch(val))
              else _walk(val, fn, in_user_data=True))
        for cle, val in value.items()
    }

#: Types MIME dont la charge est binaire : `data` y reste opaque. Tout le
#: reste — texte, JSON, media_type absent — est traverse.
#: Enumeres precisement : `application/x-` et `application/vnd.` couvraient
#: aussi `x-yaml`, `x-www-form-urlencoded` et `vnd.api+json`, qui sont du TEXTE
#: et sortaient donc en clair. Ce qui n'est pas liste est traverse.
BINARY_MEDIA_PREFIXES: tuple[str, ...] = (
    "image/", "audio/", "video/", "font/",
    "application/pdf", "application/octet-stream", "application/zip",
    "application/gzip", "application/x-tar", "application/x-bzip",
    "application/x-7z", "application/x-rar", "application/x-msdownload",
    "application/x-executable", "application/vnd.ms-",
    "application/vnd.openxmlformats", "application/vnd.oasis.opendocument",
    "application/vnd.rar", "application/vnd.android",
)

#: Cles de REPONSE porteuses de compteurs, jamais de texte.
RESPONSE_CONTROL_KEYS: frozenset[str] = frozenset({"usage", "container_id"})

#: Cles de CONTROLE du corps de requete : parametres d'inference et de
#: protocole, jamais du texte libre. Tout le reste est traverse.
#:
#: L'inverse (enumerer les surfaces a traiter) est fail-open : /v1/messages
#: accepte `stop_sequences`, `mcp_servers`, `container`, `tool_choice`, et
#: Anthropic ajoute des champs sans preavis — une capture reelle montre
#: `context_management`, `output_config`, `thinking` au premier niveau.
#:
#: Chaque entree donne les sous-cles ADMISES. Une cle inattendue dans le
#: sous-arbre fait traverser le bloc entier : l'exclusion ne vaut que pour la
#: forme connue. Sans cela, le fail-closed ne tenait qu'au premier niveau, et
#: un champ ajoute par une beta a l'interieur de `thinking` ou
#: `context_management` serait parti brut.
REQUEST_CONTROL_KEYS: dict[str, frozenset[str]] = {
    "model": frozenset(),
    "max_tokens": frozenset(),
    "temperature": frozenset(),
    "top_p": frozenset(),
    "top_k": frozenset(),
    "stream": frozenset(),
    "service_tier": frozenset(),
    "betas": frozenset(),
    "anthropic_version": frozenset(),
    # Forme SCALAIRE seulement (`container_abc123`) : le substituer empechait
    # l'amont de reutiliser le conteneur. La forme OBJET porte du texte libre
    # (`image`) et retombe donc dans la traversee.
    "container": frozenset(),
    "thinking": frozenset({"type", "budget_tokens", "display"}),
    "output_config": frozenset({"effort"}),
    "context_management": frozenset(
        {"edits", "type", "keep", "trigger", "at_least", "value",
         "clear_at_least", "clear_tool_inputs", "exclude_tools"}
    ),
}


#: Forme d'un jeton de protocole : nom de modele, de beta, de version, de
#: palier. Ni point, ni barre, ni espace — `cluster-01.acme.internal` est un
#: identifiant parfaitement valide au sens large, et passait sous `betas`, ou
#: Anthropic ignore un nom inconnu mais TRAITE quand meme la requete.
#: Une valeur qui n'a pas cette forme est TRAVERSEE : le detecteur ne modifiera
#: de toute facon pas un vrai jeton de protocole, l'erreur ne coute rien.
_CONTROL_TOKEN_RE = re.compile(r"[A-Za-z0-9_+-]{0,64}")

#: Formes plus strictes pour les cles ou l'on connait la convention exacte.
_CONTROL_VALUE_RE: dict[str, re.Pattern[str]] = {
    # `betas` est la surface la plus exposee : l'API IGNORE un nom de beta
    # inconnu et traite quand meme la requete, donc une valeur aberrante
    # partirait sans la moindre erreur visible. Tous les noms de beta
    # d'Anthropic sont horodates ; un identifiant d'infrastructure ne l'est pas.
    "betas": re.compile(r"[a-z0-9]+(?:[-.][a-z0-9]+)*-\d{4}-\d{2}-\d{2}"),
}


def _is_known_control(
    node: Any, allowed: frozenset[str], motif: re.Pattern[str] = _CONTROL_TOKEN_RE
) -> bool:
    """Le bloc a-t-il exactement la forme attendue ?

    Une CLE inconnue disqualifie le bloc, et une VALEUR textuelle qui n'a pas
    la forme d'un jeton de protocole aussi : sans ce second test, l'exclusion
    portait sur le nom du champ sans jamais regarder son contenu.
    """
    if isinstance(node, dict):
        return all(
            key in allowed and _is_known_control(value, allowed, motif)
            for key, value in node.items()
        )
    if isinstance(node, list):
        return all(_is_known_control(item, allowed, motif) for item in node)
    if isinstance(node, str):
        return motif.fullmatch(node) is not None
    return True  # nombre, booleen, null : ne peut pas porter de texte libre

#: Cles de JSON Schema qui sont structurelles, pas du texte libre.
#: On traverse `description`, on ignore la mecanique du schema : ces valeurs
#: sont recopiees VERBATIM.
#: - `$schema` / `$ref` : URLs de meta-schema. Substituees, l'API repond
#:   400 "JSON schema is invalid".
#: - `required` : liste de NOMS de proprietes. Les noms de proprietes ne sont
#:   pas substitues (contrat avec le modele) ; substituer `required` casserait
#:   la correspondance silencieusement.
#: `type` y figure pour sa forme UNION (`["string", "null"]`) : le saut par
#: SKIP_KEYS ne protegeait que la forme scalaire, et substituer les mots-cles
#: rend le schema invalide (API 400).
#: `format` prend ses valeurs dans un vocabulaire ferme : `"format": "int64"`
#: devenait un nom fictif — sans erreur, `format` etant une annotation, mais
#: c'est de la corruption silencieuse.
#: `pattern` n'y figure PAS : une regex est du texte libre, et une contrainte
#: du genre `^srv-\d+\.acme\.internal$` exposerait le domaine interne. Elle est
#: donc substituee ; le risque residuel est qu'un substitut y introduise un
#: metacaractere desequilibre, tres improbable et prefere a une fuite.
#: `dependencies` et `dependentRequired` portent des LISTES DE NOMS de
#: proprietes, exactement comme `required` : les substituer casse la
#: correspondance en silence. `$anchor` nomme une ancre locale.
SCHEMA_STRUCTURAL_KEYS: frozenset[str] = frozenset(
    {"required", "type", "format", "dependencies", "dependentRequired",
     "$anchor", "$dynamicAnchor"}
)

#: `$ref` / `$schema` : recopies tant qu'ils designent une ancre LOCALE ou le
#: vocabulaire public. Un schema herberge en interne
#: (`https://schemas.acme.corp/user.json`) est une adresse, pas une structure.
SCHEMA_REF_KEYS: frozenset[str] = frozenset({"$ref", "$schema", "$dynamicRef"})
_REF_SANS_DONNEE_RE = re.compile(r"#\S*|https?://json-schema\.org/\S*", re.I)

#: Conteneurs de sous-schemas dont les CLES sont des noms declares par l'outil :
#: on preserve les noms et on traverse chaque definition. Les traiter
#: generiquement appliquerait SKIP_KEYS a ces noms — une definition appelee
#: « name » ou « data » verrait sa description recopiee telle quelle.
SCHEMA_NAMED_SUBSCHEMAS: frozenset[str] = frozenset(
    {"properties", "$defs", "definitions", "patternProperties", "dependentSchemas"}
)

#: Cles de schema qui peuvent contenir un sous-schema (donc des `description`
#: a traverser) mais jamais de texte libre a leur racine.
SCHEMA_NESTED_KEYS: frozenset[str] = frozenset({"additionalProperties", "items"})


class UnresolvedSurrogate(Exception):
    """Leve en mode strict quand un substitut inconnu apparait en entrant."""


# --------------------------------------------------------------------------- #
# Interface de substitution
# --------------------------------------------------------------------------- #


@dataclass
class Substituter:
    """
    Adaptateur entre le walker et ton moteur de pseudonymisation.

    `to_surrogate` : texte reel -> texte avec substituts (sens sortant).
                     C'est ici que tu appelles AnonShield / Presidio / GLiNER,
                     puis ton generateur de substituts plausibles.

    `surrogates`   : mapping substitut -> valeur reelle, pour le sens entrant.
                     Alimente par la meme session. En pratique une vue sur ton
                     coffre (SQLite AnonShield, Redis, ...).

    Note : `to_surrogate` doit etre DETERMINISTE pour une session donnee.
    """

    to_surrogate: Callable[[str], str]
    surrogates: dict[str, str] = field(default_factory=dict)

    _pattern: re.Pattern[str] | None = field(default=None, init=False, repr=False)
    _pattern_size: int = field(default=-1, init=False, repr=False)

    @property
    def max_surrogate_len(self) -> int:
        """Longueur du plus long substitut. Dimensionne le tail buffer SSE."""
        return max((len(s) for s in self.surrogates), default=0)

    @property
    def pattern(self) -> re.Pattern[str] | None:
        """Alternation compilee, plus longs substituts d'abord (longest-match-first)."""
        if not self.surrogates:
            return None
        if self._pattern is None or self._pattern_size != len(self.surrogates):
            keys = sorted(self.surrogates, key=len, reverse=True)
            self._pattern = re.compile("|".join(re.escape(k) for k in keys))
            self._pattern_size = len(self.surrogates)
        return self._pattern

    def to_real(self, text: str, *, strict: bool = False) -> tuple[str, list[str]]:
        """
        Remplace tous les substituts connus par leur valeur reelle.

        Retourne (texte_resolu, substituts_inconnus_detectes).

        Les inconnus ne sont PAS remplaces (fail-closed). En mode strict, leve.
        """
        pat = self.pattern
        if pat is None:
            return text, []

        unresolved: list[str] = []

        def _sub(m: re.Match[str]) -> str:
            key = m.group(0)
            real = self.surrogates.get(key)
            if real is None:  # ne devrait pas arriver : pattern derive des cles
                unresolved.append(key)
                return key
            return real

        return pat.sub(_sub, text), unresolved


# --------------------------------------------------------------------------- #
# Traversee generique
# --------------------------------------------------------------------------- #


#: Sous-arbres dont les CLES sont choisies par l'utilisateur, pas par le
#: protocole : arguments d'outil et `metadata` (dict libre cote client).
#: SKIP_KEYS et OPAQUE_BLOCK_TYPES n'y ont aucun sens — `name`, `id`, `type`,
#: `role`, `data` y sont des noms de parametres parfaitement ordinaires
#: (`kubectl`, Terraform, tout CRUD), et les traiter comme du protocole faisait
#: sortir leur valeur en clair ET empechait sa restauration au retour :
#: l'outil s'executait alors avec le nom FICTIF.
USER_DATA_KEYS: frozenset[str] = frozenset({"input", "metadata"})

#: `name` et `id` ne sont un CONTRAT que dans un noeud de PROTOCOLE. Ailleurs
#: — dans la sortie d'un outil MCP, qui renvoie couramment
#: `{"type": …, "name": …, "uri": …}` — ce sont des donnees : les recopier
#: faisait fuir le nom reel ET empechait sa restauration au retour.
CONTRACT_KEYS: frozenset[str] = frozenset({"name", "id", "tool_use_id"})

#: Ou chaque cle de contrat est legitime, EN PLUS d'un conteneur de protocole.
#: Le type du bloc ne suffit pas — c'etait le defaut precedent — mais combine a
#: la POSITION (un bloc directement sous le `content` d'un message) il n'est
#: plus forgeable : un tiers ecrit dans un `tool_result`, deux crans plus bas.
#: `signature` n'y figure pas : sa seule position legitime est un bloc SIGNE,
#: rendu verbatim bien avant la boucle sur les cles.
CONTRACT_BLOCK_TYPES: dict[str, frozenset[str]] = {
    "name": frozenset({"tool_use", "server_tool_use", "mcp_tool_use"}),
    "id": frozenset({"tool_use", "server_tool_use", "mcp_tool_use", "message"}),
    "tool_use_id": frozenset({"tool_result", "mcp_tool_result"}),
}

#: Conteneurs dont les ENTREES sont des noeuds de protocole : le nom d'un outil
#: et celui d'un serveur MCP se retrouvent dans les noms d'outils exposes au
#: modele (`mcp__<serveur>__<outil>`), les substituer casserait le routage.
PROTOCOL_CONTAINER_KEYS: frozenset[str] = frozenset(
    {"tools", "mcp_servers", "tool_choice"}
)

#: Listes de NOMS d'outils : elles doivent correspondre exactement à ce que le
#: serveur MCP expose. Les substituer casse le filtre EN SILENCE — le modèle ne
#: peut plus déclencher l'outil réel.
TOOL_NAME_LISTS: frozenset[str] = frozenset({"allowed_tools", "disallowed_tools"})


def _walk(
    node: Any,
    fn: Callable[[str], str],
    *,
    in_schema: bool = False,
    in_user_data: bool = False,
    protocole: bool = False,
    signe_ici: bool = False,
    signe_partout: bool = False,
    dans_messages: bool = False,
    bloc_message: bool = False,
) -> Any:
    """
    Traverse recursivement une structure JSON et applique `fn` a chaque chaine
    de texte libre.

    Generique par construction : gere les types de blocs actuels ET futurs
    (server_tool_use, mcp_tool_use, web_search_tool_result, document, ...)
    sans enumeration exhaustive. Les exclusions passent par SKIP_KEYS et
    OPAQUE_BLOCK_TYPES — et ne valent QUE hors des sous-arbres de donnees
    utilisateur (USER_DATA_KEYS).
    """
    if isinstance(node, str):
        return fn(node)

    if isinstance(node, list):
        return [
            _walk(item, fn, in_schema=in_schema, in_user_data=in_user_data,
                  protocole=protocole, signe_ici=signe_ici,
                  signe_partout=signe_partout, dans_messages=dans_messages,
                  bloc_message=bloc_message)
            for item in node
        ]

    if isinstance(node, dict):
        # Bloc opaque : rendu tel quel, y compris ses enfants.
        # `type` peut porter autre chose qu'une chaine (propriete de schema
        # nommee "type", JSON arbitraire dans un tool_result) : on ne teste
        # l'appartenance que sur une chaine, sinon TypeError (non hashable).
        # Un bloc signe n'est produit que par l'API, et ne revient que dans le
        # `content` d'un message ASSISTANT. Partout ailleurs — sortie d'un
        # serveur MCP relayee dans un `tool_result`, message utilisateur,
        # `system`, definition d'outil — `type` est une valeur que le client ou
        # un tiers ECRIT : l'opacite y est FORGEABLE, et rendait tout le
        # sous-arbre verbatim. Restreindre a `input`/`metadata` ne fermait que
        # deux de ces surfaces.
        btype = node.get("type")
        if (signe_ici or signe_partout) and not in_user_data \
                and isinstance(btype, str) and btype in OPAQUE_BLOCK_TYPES:
            return node

        # `data` protege une charge BINAIRE (image, PDF). Une source de
        # document peut aussi etre du TEXTE : `{"type": "text", "data": "..."}`.
        # La regle est fail-CLOSED : on ne saute `data` que si la charge est
        # EXPLICITEMENT binaire. Exiger `media_type` commencant par `text/`
        # laissait fuir les cas sans media_type, avec `application/json`, ou
        # avec une casse differente (les types MIME sont insensibles a la
        # casse, RFC 2045).
        media = node.get("media_type")
        media = media.lower() if isinstance(media, str) else ""
        # `type == "base64"` dit comment la charge est ENCODEE, pas ce qu'elle
        # contient. Le prendre pour une preuve de binarite faisait recopier
        # verbatim tout document texte encode — un JSON de configuration colle
        # dans un prompt partait entier. Seul le media_type fait foi.
        binaire = media.startswith(BINARY_MEDIA_PREFIXES)
        texte_brut = "data" in node and not binaire

        out: dict[str, Any] = {}
        for key, value in node.items():
            if not in_user_data:
                formes = STRUCTURED_SKIP_KEYS.get(key)
                if formes is not None:
                    # Une forme INCONNUE est de la donnee posee par le client :
                    # la traverser en mode protocole y aurait laisse `type`
                    # verbatim, qui est justement ce qu'un client peut y ecrire.
                    out[key] = (
                        value if _forme_connue(value, formes)
                        else _traverse_hors_forme(value, fn, formes)
                    )
                    continue

                # Une cle de vocabulaire FERME ne reste verbatim que si sa
                # valeur appartient a ce vocabulaire. Sans cette garde, elle
                # etait recopiee quoi qu'elle porte, donc forgeable.
                # Dans un SCHEMA, ces cles sont structurelles et traitees
                # plus bas : `type` y vaut couramment `["string", "null"]`,
                # que cette garde aurait substitue — schema invalide, 400.
                forme = None if in_schema else SCALAR_SKIP_FORMS.get(key)
                if forme is not None:
                    if isinstance(value, str) and forme.fullmatch(value):
                        out[key] = value
                        continue
                    out[key] = _walk(value, fn, in_user_data=True)
                    continue

                # Une charge base64 dont le media est du TEXTE (JSON, YAML,
                # CSV...) est decodee, pseudonymisee, puis re-encodee. La
                # laisser verbatim parce qu'elle est encodee envoyait le
                # fichier ENTIER en clair — l'amont, lui, le decode ; et la
                # traverser telle quelle n'aurait rien donne, le detecteur ne
                # lisant pas du base64.
                if key == "data" and isinstance(value, str) \
                        and btype == "base64" and not binaire:
                    out[key] = _base64_texte(value, fn)
                    continue

                # Un noeud est protocolaire s'il HERITE d'un conteneur de
                # protocole, ou s'il occupe une POSITION de protocole : un bloc
                # directement sous le `content` d'un message, ou un message
                # lui-meme. Le deduire du `type` du noeud etait forgeable —
                # meme classe que l'opacite : un tiers ecrit
                # `{"type": "tool_use", "name": "<hote reel>"}` dans son
                # sous-arbre et les deux valeurs sortent verbatim.
                contrat = protocole or dans_messages or (
                    bloc_message and isinstance(btype, str)
                    and btype in CONTRACT_BLOCK_TYPES.get(key, frozenset()))
                if key in SKIP_KEYS and (key not in CONTRACT_KEYS or contrat) \
                        and not (key == "data" and texte_brut):
                    # Le saut ne vaut que pour un SCALAIRE protocolaire. Ces
                    # cles portent parfois une structure — `cache_control`
                    # s'enrichit (`{"type": "ephemeral", "ttl": "5m"}`). La
                    # recopier verbatim laissait sortir tout son sous-arbre
                    # sans passer par le detecteur.
                    if not isinstance(value, (dict, list)):
                        out[key] = value
                        continue

                if protocole and key in TOOL_NAME_LISTS and isinstance(value, list) \
                        and all(isinstance(item, str) for item in value):
                    out[key] = value
                    continue

            # Les noms de proprietes d'un schema sont un contrat avec le modele :
            # on preserve les cles et on traverse chaque definition. Teste AVANT
            # SCHEMA_STRUCTURAL_KEYS (qui contient "properties") : sinon la
            # traversee generique appliquerait SKIP_KEYS aux NOMS de proprietes
            # et laisserait passer la description d'une propriete nommee
            # "name" / "id" / "data".
            if in_schema and key in SCHEMA_NAMED_SUBSCHEMAS and isinstance(value, dict):
                # Les cles de `patternProperties` sont des REGEX, pas des noms
                # declares : elles peuvent porter un littéral d'hote.
                nom = fn if key == "patternProperties" else (lambda p: p)
                out[key] = {
                    nom(pname): _walk(pdef, fn, in_schema=True)
                    for pname, pdef in value.items()
                }
                continue

            if in_schema and key in SCHEMA_REF_KEYS:
                out[key] = value if (
                    isinstance(value, str) and _REF_SANS_DONNEE_RE.fullmatch(value)
                ) else _walk(value, fn, in_schema=True)
                continue

            # A l'interieur d'un JSON Schema, on ne touche qu'aux descriptions
            # et aux valeurs d'enum ; le reste est structurel.
            if in_schema and key in SCHEMA_STRUCTURAL_KEYS:
                out[key] = value
                continue

            if in_schema and key in SCHEMA_NESTED_KEYS:
                out[key] = (
                    _walk(value, fn, in_schema=True)
                    if isinstance(value, (dict, list))
                    else value
                )
                continue

            entering_schema = in_schema or key == "input_schema"
            out[key] = _walk(
                value, fn,
                in_schema=entering_schema,
                in_user_data=in_user_data or key in USER_DATA_KEYS,
                # HERITE : `mcp_servers[].tool_configuration.allowed_tools` est
                # deux crans sous son conteneur. La propagation s'arrete aux
                # frontieres de donnees — un `content` sous une racine de
                # reponse ne devient PAS protocolaire — et a l'entree d'un
                # SCHEMA : `default`, `example`, `const` y portent des valeurs
                # d'exemple, ou `name` et `id` sont des donnees, jamais des
                # cles de routage.
                protocole=False if entering_schema
                else (protocole or key in PROTOCOL_CONTAINER_KEYS),
                # Le seul emplacement ou un bloc signe est legitime. La
                # legitimite est une propriete de POSITION : elle se descend
                # depuis la racine `messages`, elle ne se deduit PAS du dict
                # courant. Tester le seul `role` la rendait FORGEABLE — un
                # serveur MCP place `{"role": "assistant", "content": [...]}`
                # dans un `tool_result` et le sous-arbre ressort verbatim.
                # `dans_messages` retombe a False sous ce niveau : un `content`
                # imbrique porte de nouveau des donnees.
                signe_ici=(dans_messages and key == "content"
                           and node.get("role") == "assistant"),
                # Un BLOC de message occupe une position de protocole : c'est
                # la que `tool_use.name` et `tool_result.tool_use_id` sont des
                # cles de routage. Ailleurs, ce sont des donnees.
                bloc_message=(dans_messages and key == "content"),
                signe_partout=signe_partout,
            )
        return out

    # int, float, bool, None
    return node


# --------------------------------------------------------------------------- #
# SORTANT : Claude Code -> Anthropic
# --------------------------------------------------------------------------- #


def walk_request(body: dict[str, Any], sub: Substituter) -> dict[str, Any]:
    """
    Pseudonymise un corps de requete /v1/messages (ou /v1/messages/count_tokens,
    meme forme).

    Couvre les quatre surfaces, dont les deux systematiquement oubliees :

      1. `system`            : chaine OU liste de blocs (avec cache_control)
      2. `messages[].content`: chaine OU liste de blocs, dont `tool_use.input`
                               et `tool_result.content`
      3. `tools[]`           : *** description ET input_schema ***
                               Repart INTEGRALEMENT a chaque requete. Les
                               descriptions d'outils MCP contiennent souvent
                               des noms d'hotes internes. Fuite la plus discrete.
      4. `metadata`          : `user_id` notamment

    IMPORTANT : `walk_request` doit etre appele sur le corps COMPLET, y compris
    l'historique. Claude Code renvoie toute la conversation a chaque tour ; ne
    traiter que le dernier message laisse fuir tout le reste.

    La traversee est FAIL-CLOSED : tout est traverse sauf REQUEST_CONTROL_KEYS.
    Un champ ajoute par l'API demain est donc pseudonymise par defaut, pas
    laisse en clair.
    """
    if not isinstance(body, dict):
        # `body.items()` levait `AttributeError`/`TypeError`, que le proxy ne
        # rattrape pas : 500 non structure au lieu d'un refus lisible.
        raise ValueError(f"corps de requete inattendu : {type(body).__name__}")

    out = dict(body)

    for key, value in body.items():
        allowed = REQUEST_CONTROL_KEYS.get(key)
        motif = _CONTROL_VALUE_RE.get(key, _CONTROL_TOKEN_RE)
        if allowed is not None and _is_known_control(value, allowed, motif):
            continue
        # `walk_request` attaque la RACINE : la cle n'est traversee par personne,
        # c'est ici qu'il faut reconnaitre `metadata`.
        out[key] = _walk(value, sub.to_surrogate,
                         in_user_data=key in USER_DATA_KEYS,
                         protocole=key in PROTOCOL_CONTAINER_KEYS,
                         dans_messages=key == "messages")

    return out


# --------------------------------------------------------------------------- #
# ENTRANT non-streaming : Anthropic -> Claude Code
# --------------------------------------------------------------------------- #


def walk_response(
    body: dict[str, Any], sub: Substituter, *, strict: bool = False
) -> tuple[dict[str, Any], list[str]]:
    """
    Restaure les valeurs reelles dans une reponse non-streamee.

    Retourne (corps_resolu, substituts_inconnus).

    Les `tool_use.input` sont resolus ici : sans cela, l'agent executerait
    ses commandes contre des ressources inexistantes.

    La restauration couvre TOUT le corps, pas seulement `content` : un
    substitut peut apparaitre dans un message d'erreur amont ou dans l'echo
    de `stop_sequence`. Ne pas le restaurer laisse l'operateur devant un nom
    d'hote qui n'existe pas.
    """
    if not isinstance(body, dict):
        # Une page d'erreur amont peut etre un JSON valide qui n'est pas un
        # objet. `dict(body)` y levait TypeError, que le proxy ne rattrape
        # pas : 500 non structure au lieu du fail-closed prevu.
        raise ValueError(f"corps de reponse inattendu : {type(body).__name__}")

    unresolved: list[str] = []

    def _resolve(text: str) -> str:
        resolved, missing = sub.to_real(text, strict=strict)
        unresolved.extend(missing)
        return resolved

    out = dict(body)
    for key, value in body.items():
        if key in RESPONSE_CONTROL_KEYS:
            continue
        # Au RETOUR, l'opacite reste permissive : le corps vient d'Anthropic,
        # un bloc signe qui s'y trouve n'a pas ete pose par un tiers, et la
        # restauration ne fait jamais SORTIR de valeur. Le risque s'inverse —
        # traverser un bloc signe invaliderait sa signature (D3), panne dure.
        out[key] = _walk(value, _resolve, in_user_data=key in USER_DATA_KEYS,
                         protocole=key in PROTOCOL_CONTAINER_KEYS,
                         signe_partout=True, bloc_message=key == "content")

    if strict and unresolved:
        raise UnresolvedSurrogate(f"substituts inconnus : {sorted(set(unresolved))}")

    return out, unresolved


# --------------------------------------------------------------------------- #
# ENTRANT streaming : SSE
# --------------------------------------------------------------------------- #


@dataclass
class _TextBuffer:
    """
    Tail buffer pour les `text_delta`.

    Un substitut peut etre coupe entre deux chunks SSE
    ("srv-billing" | "-prod"). On retient toujours les `keep` derniers
    caracteres et on n'emet que ce qui est certainement complet. Si un
    substitut complet chevauche le point de coupe, on etend la coupe pour
    l'inclure entierement.
    """

    sub: Substituter
    keep: int
    buf: str = ""

    def feed(self, text: str) -> tuple[str, list[str]]:
        self.buf += text
        limit = len(self.buf) - self.keep
        if limit <= 0:
            return "", []

        cut = limit
        pat = self.sub.pattern
        if pat is not None:
            for m in pat.finditer(self.buf):
                if m.start() < cut < m.end():
                    cut = m.end()  # n'ampute jamais un substitut complet
                    break

        head, self.buf = self.buf[:cut], self.buf[cut:]
        return self.sub.to_real(head)

    def flush(self) -> tuple[str, list[str]]:
        head, self.buf = self.buf, ""
        if not head:
            return "", []
        return self.sub.to_real(head)


@dataclass
class SSERewriter:
    """
    Reecrit un flux SSE Anthropic en restaurant les valeurs reelles.

    Usage
    -----
        rw = SSERewriter(sub)
        for raw_event in upstream_sse_lines():
            for out_event in rw.feed(raw_event):
                yield out_event
        if rw.unresolved:
            log.error("substituts inconnus: %s", rw.unresolved)

    Deux regimes distincts, volontairement asymetriques :

      * `text_delta`       -> resolu au fil de l'eau (tail buffer). L'operateur
                              doit voir le texte s'afficher en direct.
      * `input_json_delta` -> AUCUNE resolution pendant le streaming. On
                              accumule, et a `content_block_stop` on parse,
                              on valide, on resout, on emet un delta unique.
                              Personne ne consomme des arguments d'outil avant
                              la fermeture du bloc : rien a gagner a streamer,
                              tout a perdre a resoudre du JSON incomplet.
      * `thinking_delta` /
        `signature_delta`  -> passthrough strict. Signature verifiee en amont.
    """

    sub: Substituter
    unresolved: list[str] = field(default_factory=list)

    _text: dict[int, _TextBuffer] = field(default_factory=dict, init=False)
    _json: dict[int, list[str]] = field(default_factory=dict, init=False)

    # -- API ---------------------------------------------------------------- #

    def feed(self, event: dict[str, Any]) -> Iterator[dict[str, Any]]:
        """
        Consomme un evenement SSE deserialise, emet zero ou plusieurs
        evenements a transmettre au client.
        """
        etype = event.get("type")

        if etype == "content_block_start":
            yield from self._on_block_start(event)

        elif etype == "content_block_delta":
            yield from self._on_delta(event)

        elif etype == "content_block_stop":
            yield from self._on_block_stop(event)

        elif etype in ("message_delta", "error", "message_start", "message_stop"):
            if etype in ("message_delta", "message_stop"):
                # Le message se termine : ce qui reste dans les accumulateurs
                # doit sortir AVANT. Vider en fin de flux seulement plaçait ces
                # deltas APRES `message_stop` — hors protocole, donc ignorés en
                # silence par le client, ou fatals selon son parseur.
                yield from self.close()
            # Memes surfaces que walk_response hors `content` : l'echo de
            # `stop_sequence` et les messages d'erreur portent des substituts.
            out = dict(event)
            for key, value in event.items():
                if key in RESPONSE_CONTROL_KEYS or key == "type":
                    continue
                out[key] = _walk(value, self._resolve,
                                 in_user_data=key in USER_DATA_KEYS,
                                 signe_partout=True)
            yield out

        else:
            # `ping`, et TOUT type d'evenement ajoute par l'API. Le rendre
            # verbatim laissait ses substituts non restaures : l'operateur
            # voyait le nom FICTIF, et un outil s'y serait execute. Un type
            # inconnu est justement celui qu'aucun test ne couvre.
            out = dict(event)
            for key, value in event.items():
                if key in RESPONSE_CONTROL_KEYS or key == "type":
                    continue
                out[key] = _walk(value, self._resolve,
                                 in_user_data=key in USER_DATA_KEYS,
                                 signe_partout=True)
            yield out

    # -- interne ------------------------------------------------------------ #

    #: Deltas dont le contenu est RESOLU. Liste positive : D3 est un invariant
    #: VERROUILLE, la restauration d'un delta inconnu n'en est pas un. Un
    #: `redacted_thinking_delta` ajoute demain serait modifie par une liste
    #: d'exclusion, sa signature invalidee, et le tour suivant refuse par
    #: l'amont — panne dure contre un simple substitut affiche a l'operateur.
    _DELTAS_RESOLUS: frozenset[str] = frozenset(
        {"text_delta", "input_json_delta", "citations_delta"}
    )

    def _resolve(self, text: str) -> str:
        resolved, missing = self.sub.to_real(text)
        self.unresolved.extend(missing)
        return resolved

    def _on_block_start(self, event: dict[str, Any]) -> Iterator[dict[str, Any]]:
        idx = event.get("index", 0)
        # Un champ present mais NUL fait planter la generatrice SSE, qui meurt
        # sans emettre d'evenement `error` : le client perd le flux en silence.
        block = event.get("content_block") or {}
        btype = block.get("type") if isinstance(block, dict) else None

        if btype == "text":
            self._text[idx] = _TextBuffer(
                self.sub, keep=self.sub.max_surrogate_len
            )
        elif btype in ("tool_use", "server_tool_use", "mcp_tool_use"):
            self._json[idx] = []

        # L'evenement de demarrage n'est pas vide : `mcp_tool_use.server_name`,
        # `web_search_tool_result.content[].url` et parfois `input` y sont deja
        # remplis. Les emettre verbatim montrait le SUBSTITUT a l'operateur, la
        # ou walk_response restaure le meme bloc.
        if block:
            event = {**event, "content_block": _walk(
                block, self._resolve, signe_partout=True, bloc_message=True)}
        yield event

    def _on_delta(self, event: dict[str, Any]) -> Iterator[dict[str, Any]]:
        idx = event.get("index", 0)
        delta = event.get("delta") or {}
        if not isinstance(delta, dict):
            yield event
            return
        dtype = delta.get("type")

        if dtype == "text_delta":
            # L'accumulateur est cree A LA VOLEE : un delta sans
            # `content_block_start` correspondant partait sinon brut, substituts
            # non resolus.
            buffer = self._text.get(idx)
            if buffer is None:
                buffer = self._text[idx] = _TextBuffer(
                    self.sub, keep=self.sub.max_surrogate_len
                )
            resolved, missing = buffer.feed(delta.get("text") or "")
            self.unresolved.extend(missing)
            if resolved:
                out = dict(event)
                out["delta"] = {**delta, "text": resolved}
                yield out
            # rien a emettre : le tail buffer retient encore le contenu
            return

        if dtype == "input_json_delta":
            # On accumule, on n'emet RIEN. Resolution atomique au stop (D2).
            fragment = delta.get("partial_json")
            self._json.setdefault(idx, []).append(
                fragment if isinstance(fragment, str) else ""
            )
            return

        if dtype in self._DELTAS_RESOLUS:
            out = dict(event)
            out["delta"] = _walk(delta, self._resolve, signe_partout=True)
            yield out
            return

        # Type inconnu : passthrough. Il peut etre SIGNE (D3).
        yield event

    def _on_block_stop(self, event: dict[str, Any]) -> Iterator[dict[str, Any]]:
        idx = event.get("index", 0)

        if idx in self._text:
            resolved, missing = self._text.pop(idx).flush()
            self.unresolved.extend(missing)
            if resolved:
                yield {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {"type": "text_delta", "text": resolved},
                }

        # `if` et non `elif` : un amont incoherent peut annoncer un bloc `text`
        # puis envoyer des `input_json_delta` sur le meme index. Le JSON
        # accumule etait alors perdu sans laisser de trace.
        if idx in self._json:
            raw = "".join(self._json.pop(idx))
            payload = self._resolve_tool_args(raw)
            if payload:
                yield {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {"type": "input_json_delta", "partial_json": payload},
                }

        yield event

    def close(self) -> Iterator[dict[str, Any]]:
        """Vide les accumulateurs restes ouverts en fin de flux.

        Un `content_block_stop` dont l'`index` ne correspond a aucun bloc
        laissait le tampon accroche : le texte deja accumule n'etait jamais
        emis, et l'operateur perdait la fin du message SANS aucun signe.
        """
        for idx in list(self._text):
            resolved, missing = self._text.pop(idx).flush()
            self.unresolved.extend(missing)
            if resolved:
                yield {"type": "content_block_delta", "index": idx,
                       "delta": {"type": "text_delta", "text": resolved}}
        for idx in list(self._json):
            payload = self._resolve_tool_args("".join(self._json.pop(idx)))
            if payload:
                yield {"type": "content_block_delta", "index": idx,
                       "delta": {"type": "input_json_delta", "partial_json": payload}}

    def _resolve_tool_args(self, raw: str) -> str:
        """
        Parse le JSON complet, resout, re-serialise.

        En cas de JSON invalide (flux tronque, erreur amont), on renvoie le brut
        sans resolution : mieux vaut un outil qui echoue sur un substitut qu'un
        payload silencieusement corrompu.
        """
        if not raw.strip():
            return raw

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            self.unresolved.append("<json_invalide>")
            return raw

        def _resolve(text: str) -> str:
            resolved, missing = self.sub.to_real(text)
            self.unresolved.extend(missing)
            return resolved

        # La racine EST l'argument d'outil : aucune cle n'y est protocolaire.
        return json.dumps(
            _walk(parsed, _resolve, in_user_data=True), ensure_ascii=False
        )


# --------------------------------------------------------------------------- #
# Notes d'integration
# --------------------------------------------------------------------------- #
#
# 1. Ce module ne couvre QUE le canal 1 (trafic modele). Le canal 2 — Bash,
#    WebFetch, serveurs MCP appelant le reseau directement — ne passe jamais
#    par ici. Seul un hook PreToolUse peut l'empecher d'atteindre le reseau.
#    L'affaire Grok Build de juillet 2026 est la demonstration : 5,1 Go
#    exfiltres par un canal de stockage totalement distinct de l'API
#    d'inference, pendant que la tache generait 192 Ko de trafic modele.
#
# 2. Valide en capturant TOUT le trafic sortant du processus (mitmproxy), pas
#    seulement ce que ce walker transforme. C'est un test de non-regression a
#    part entiere.
#
# 3. `SKIP_KEYS` contient `name`. Si tes noms d'outils MCP encodent des noms de
#    services internes (ex. `payments_api__query`), c'est une fuite. Traite-la
#    au niveau du serveur MCP, pas ici : renommer un outil en cours de route
#    casserait la correspondance avec `tool_use.name` au retour.
#
# 4. Le determinisme de `to_surrogate` conditionne le cache de prompt. Verifie
#    en integration que deux requetes identiques produisent un corps sortant
#    strictement identique, octet pour octet.
#
# 5. Fail-closed : `.unresolved` non vide APRES un tour signifie que le modele
#    a invente un substitut. Ne devine jamais. Laisse l'outil echouer et
#    remonte l'erreur au modele, il se corrigera.
