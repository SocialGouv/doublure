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

#: Cles dont la VALEUR ne doit jamais etre substituee.
#: - identifiants de protocole (id, tool_use_id, signature) : casseraient l'API
#: - `name` : nom d'outil, contrat avec le modele, pas une donnee
#: - `data` / `media_type` : payloads base64 d'images et documents
#: - `type` : discriminant de bloc
SKIP_KEYS: frozenset[str] = frozenset(
    {
        "type",
        "id",
        "tool_use_id",
        "signature",
        "name",
        "media_type",
        "data",
        "cache_control",
        "model",
        "stop_reason",
        "role",
    }
)

#: Types MIME dont la charge est binaire : `data` y reste opaque. Tout le
#: reste — texte, JSON, media_type absent — est traverse.
BINARY_MEDIA_PREFIXES: tuple[str, ...] = (
    "image/", "audio/", "video/", "font/",
    "application/pdf", "application/octet-stream", "application/zip",
    "application/gzip", "application/x-", "application/vnd.",
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
    "thinking": frozenset({"type", "budget_tokens", "display"}),
    "output_config": frozenset({"effort"}),
    "context_management": frozenset(
        {"edits", "type", "keep", "trigger", "at_least", "value",
         "clear_at_least", "clear_tool_inputs", "exclude_tools"}
    ),
}


def _is_known_control(node: Any, allowed: frozenset[str]) -> bool:
    """Le bloc a-t-il exactement la forme attendue ?

    Les feuilles scalaires sont admises telles quelles (parametres
    d'inference, noms de beta) ; seule une CLE inconnue disqualifie le bloc.
    """
    if isinstance(node, dict):
        return all(
            key in allowed and _is_known_control(value, allowed)
            for key, value in node.items()
        )
    if isinstance(node, list):
        return all(_is_known_control(item, allowed) for item in node)
    return True

#: Cles de JSON Schema qui sont structurelles, pas du texte libre.
#: On traverse `description`, on ignore la mecanique du schema : ces valeurs
#: sont recopiees VERBATIM.
#: - `$schema` / `$ref` : URLs de meta-schema. Substituees, l'API repond
#:   400 "JSON schema is invalid".
#: - `required` : liste de NOMS de proprietes. Les noms de proprietes ne sont
#:   pas substitues (contrat avec le modele) ; substituer `required` casserait
#:   la correspondance silencieusement.
SCHEMA_STRUCTURAL_KEYS: frozenset[str] = frozenset(
    {"required", "$schema", "$ref"}
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


def _walk(node: Any, fn: Callable[[str], str], *, in_schema: bool = False) -> Any:
    """
    Traverse recursivement une structure JSON et applique `fn` a chaque chaine
    de texte libre.

    Generique par construction : gere les types de blocs actuels ET futurs
    (server_tool_use, mcp_tool_use, web_search_tool_result, document, ...)
    sans enumeration exhaustive. Les exclusions passent par SKIP_KEYS et
    OPAQUE_BLOCK_TYPES.
    """
    if isinstance(node, str):
        return fn(node)

    if isinstance(node, list):
        return [_walk(item, fn, in_schema=in_schema) for item in node]

    if isinstance(node, dict):
        # Bloc opaque : rendu tel quel, y compris ses enfants.
        # `type` peut porter autre chose qu'une chaine (propriete de schema
        # nommee "type", JSON arbitraire dans un tool_result) : on ne teste
        # l'appartenance que sur une chaine, sinon TypeError (non hashable).
        btype = node.get("type")
        if isinstance(btype, str) and btype in OPAQUE_BLOCK_TYPES:
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
        binaire = btype == "base64" or media.startswith(BINARY_MEDIA_PREFIXES)
        texte_brut = "data" in node and not binaire

        out: dict[str, Any] = {}
        for key, value in node.items():
            if key in SKIP_KEYS and not (key == "data" and texte_brut):
                out[key] = value
                continue

            # Les noms de proprietes d'un schema sont un contrat avec le modele :
            # on preserve les cles et on traverse chaque definition. Teste AVANT
            # SCHEMA_STRUCTURAL_KEYS (qui contient "properties") : sinon la
            # traversee generique appliquerait SKIP_KEYS aux NOMS de proprietes
            # et laisserait passer la description d'une propriete nommee
            # "name" / "id" / "data".
            if in_schema and key == "properties" and isinstance(value, dict):
                out[key] = {
                    pname: _walk(pdef, fn, in_schema=True)
                    for pname, pdef in value.items()
                }
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
            out[key] = _walk(value, fn, in_schema=entering_schema)
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
    out = dict(body)

    for key, value in body.items():
        allowed = REQUEST_CONTROL_KEYS.get(key)
        if allowed is not None and _is_known_control(value, allowed):
            continue
        out[key] = _walk(value, sub.to_surrogate)

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
    unresolved: list[str] = []

    def _resolve(text: str) -> str:
        resolved, missing = sub.to_real(text, strict=strict)
        unresolved.extend(missing)
        return resolved

    out = dict(body)
    for key, value in body.items():
        if key in RESPONSE_CONTROL_KEYS:
            continue
        out[key] = _walk(value, _resolve)

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

        elif etype in ("message_delta", "error"):
            # Memes surfaces que walk_response hors `content` : l'echo de
            # `stop_sequence` et les messages d'erreur portent des substituts.
            def _resolve(text: str) -> str:
                resolved, missing = self.sub.to_real(text)
                self.unresolved.extend(missing)
                return resolved

            out = dict(event)
            for key, value in event.items():
                if key in RESPONSE_CONTROL_KEYS or key == "type":
                    continue
                out[key] = _walk(value, _resolve)
            yield out

        else:
            # message_start, message_stop, ping
            yield event

    # -- interne ------------------------------------------------------------ #

    def _on_block_start(self, event: dict[str, Any]) -> Iterator[dict[str, Any]]:
        idx = event.get("index", 0)
        block = event.get("content_block", {})
        btype = block.get("type")

        if btype == "text":
            self._text[idx] = _TextBuffer(
                self.sub, keep=self.sub.max_surrogate_len
            )
        elif btype in ("tool_use", "server_tool_use", "mcp_tool_use"):
            self._json[idx] = []

        yield event

    def _on_delta(self, event: dict[str, Any]) -> Iterator[dict[str, Any]]:
        idx = event.get("index", 0)
        delta = event.get("delta", {})
        dtype = delta.get("type")

        if dtype == "text_delta" and idx in self._text:
            resolved, missing = self._text[idx].feed(delta.get("text", ""))
            self.unresolved.extend(missing)
            if resolved:
                out = dict(event)
                out["delta"] = {**delta, "text": resolved}
                yield out
            # rien a emettre : le tail buffer retient encore le contenu
            return

        if dtype == "input_json_delta" and idx in self._json:
            # On accumule, on n'emet RIEN. Resolution atomique au stop.
            self._json[idx].append(delta.get("partial_json", ""))
            return

        # thinking_delta, signature_delta, et tout type futur : passthrough.
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

        elif idx in self._json:
            raw = "".join(self._json.pop(idx))
            payload = self._resolve_tool_args(raw)
            if payload:
                yield {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {"type": "input_json_delta", "partial_json": payload},
                }

        yield event

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

        return json.dumps(_walk(parsed, _resolve), ensure_ascii=False)


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
