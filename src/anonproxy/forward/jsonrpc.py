"""Pseudonymising an MCP body — JSON-RPC in, JSON-RPC out.

JSON-RPC has the shape this project has already been burnt by five times: a
thin envelope that must stay verbatim, wrapped around free-form data where a
KEY carries as much as a value does.

So the rule is the one the walker reached the hard way: **a key is protocol by
its POSITION, never by its name.** `id` at the message level correlates the
response; `id` inside `params` is a customer record. Deriving the answer from
the key name is what let a hostile server forge protection for its own subtree,
four rounds running.

**Accepted leak, stated rather than discovered**: `params.name` stays verbatim.
It is the routing key an MCP server dispatches on, and substituting it breaks
the call silently — the same arbitration as `tools[].name` on the Anthropic
side, and the same reason: it is a naming convention, not a value.

**Deliberate breakage**: everything else under `params` is substituted, URIs
included, even though a remote server cannot resolve a fictional one. A call
that fails is VISIBLE — the agent stumbles and the operator sees it. A value
that leaves is silent. That asymmetry is the whole project, and it is not
suspended because a call is inconvenient.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import json
from typing import Callable

#: Clés du protocole, au NIVEAU DU MESSAGE uniquement.
_ENVELOPPE = frozenset({"jsonrpc", "id", "method"})
#: Clé de routage d'un appel d'outil : verbatim, fuite assumée.
_ROUTAGE = frozenset({"name"})
#: Sous-arbres de données libres d'un message JSON-RPC.
_DONNEES = frozenset({"params", "result", "error"})
#: Champs où MCP range une charge encodée, et la clé qui dit ce qu'elle
#: contient. `mimeType` est la forme camelCase du protocole MCP.
_CHARGES = ("blob", "data", "content")
_TYPES_MIME = ("mimeType", "mime_type", "media_type", "mimetype")
#: Seul un type MIME TEXTUEL autorise la traversée : décoder puis ré-encoder
#: un PNG le corrigerait. Même arbitrage que le walker Anthropic (round 12).
_MIME_TEXTUELS = ("text/", "application/json", "application/xml",
                  "application/yaml", "application/x-yaml")


class BinaryBody(RuntimeError):
    """Ce corps n'est pas du texte : il ne peut être ni relu ni réécrit."""


class JsonRpcTransform:
    """`BodyTransform` pour un canal MCP.

    Les deux sens ne sont pas symétriques et ne doivent jamais l'être : ce qui
    sort est pseudonymisé, ce qui entre est restauré.
    """

    def __init__(self, to_surrogate: Callable[[str], str],
                 to_real: Callable[[str], str]):
        self._sortant = to_surrogate
        self._entrant = to_real

    # ------------------------------------------------------------------ sens

    def outgoing(self, host: str, headers: dict[str, str], body: bytes) -> bytes:
        return self._appliquer(body, self._sortant, headers)

    def incoming(self, host: str, headers: dict[str, str], body: bytes) -> bytes:
        return self._appliquer(body, self._entrant, headers)

    # --------------------------------------------------------------- moteur

    def _appliquer(self, body: bytes, transformer: Callable[[str], str],
                   headers: dict[str, str] | None = None) -> bytes:
        if not body:
            return body
        # Un corps gzipé est du TEXTE compressé. Sans le détendre, il levait
        # `BinaryBody` — que l'échange ne rattrape pas — et la connexion
        # mourait sans 502, sur une réponse parfaitement ordinaire.
        comprime = (headers or {}).get("content-encoding", "").lower() in (
            "gzip", "x-gzip")
        if comprime:
            try:
                body = gzip.decompress(body)
            except (OSError, EOFError) as exc:
                raise BinaryBody(f"corps gzip illisible : {exc}") from exc
        rendu = self._appliquer_clair(body, transformer)
        return gzip.compress(rendu) if comprime else rendu

    def _appliquer_clair(self, body: bytes,
                         transformer: Callable[[str], str]) -> bytes:
        try:
            texte = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            # Sur une destination déclarée À INSPECTER, relayer ce qu'on ne
            # sait pas lire dirait que ça a été lu.
            raise BinaryBody("corps non textuel : il ne peut pas être relu") from exc
        try:
            message = json.loads(texte)
        except (json.JSONDecodeError, ValueError):
            # Un corps tronqué ou un format tiers reste du TEXTE : le protéger
            # entier est le sens sûr, et ça ne tue pas la connexion.
            return transformer(texte).encode("utf-8")
        # UN seul niveau de lot, ce que dit la spec. En descendant plus loin,
        # tout dict interne recevait le traitement d'enveloppe — `id` et
        # `method` verbatim, alors que ce sont des données à cette profondeur.
        if isinstance(message, list):
            rendu = [self._message(m, transformer) for m in message]
        else:
            rendu = self._message(message, transformer)
        return json.dumps(rendu, ensure_ascii=False).encode("utf-8")

    def _message(self, noeud, transformer):
        """Niveau MESSAGE : l'enveloppe est du protocole, le reste des données."""
        if not isinstance(noeud, dict):
            return self._libre(noeud, transformer)
        rendu = {}
        for cle, valeur in noeud.items():
            if cle in _ENVELOPPE:
                rendu[cle] = valeur
            elif cle in _DONNEES:
                rendu[cle] = self._donnees(valeur, transformer)
            else:
                rendu[cle] = self._libre(valeur, transformer)
        return rendu

    def _donnees(self, noeud, transformer):
        """Premier niveau sous `params`/`result` : seule la clé de ROUTAGE y
        est du protocole, et uniquement à ce niveau."""
        if not isinstance(noeud, dict):
            return self._libre(noeud, transformer)
        return {
            transformer(cle) if cle not in _ROUTAGE else cle:
                valeur if cle in _ROUTAGE else self._libre(valeur, transformer)
            for cle, valeur in noeud.items()
        }

    def _charge_encodee(self, source: dict, rendu: dict, transformer):
        """Traverse une charge base64 quand une CLÉ VOISINE la dit textuelle.

        Un serveur MCP range le contenu d'une ressource sous `blob`, avec son
        type MIME à côté. Traité comme une chaîne opaque, le fichier traversait
        VERBATIM dans les deux sens — la lecture d'une ressource rendait le
        document brut à l'agent, et son écriture le sortait tel quel.
        """
        mime = next((str(source[c]) for c in _TYPES_MIME if c in source), "")
        if not mime.lower().startswith(_MIME_TEXTUELS):
            return rendu
        for champ in _CHARGES:
            valeur = source.get(champ)
            if not isinstance(valeur, str):
                continue
            try:
                clair = base64.b64decode(valeur, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue  # pas du base64 textuel : la chaîne a déjà été traitée
            rendu[transformer(champ)] = base64.b64encode(
                transformer(clair).encode("utf-8")).decode("ascii")
        return rendu

    def _libre(self, noeud, transformer):
        """Données libres : la clé est une valeur comme une autre."""
        if isinstance(noeud, dict):
            rendu = {transformer(c): self._libre(v, transformer)
                     for c, v in noeud.items()}
            return self._charge_encodee(noeud, rendu, transformer)
        if isinstance(noeud, list):
            return [self._libre(v, transformer) for v in noeud]
        if isinstance(noeud, str):
            return transformer(noeud)
        # Les nombres, booléens et null ne portent pas d'identifiant : les
        # traverser en texte les transformerait en chaînes et casserait le
        # schéma attendu par le serveur.
        return noeud
