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
import re
import zlib
from typing import Callable

#: Clés du protocole, au NIVEAU DU MESSAGE uniquement.
_ENVELOPPE = frozenset({"jsonrpc", "id", "method"})
#: Clé de routage d'un appel d'outil : verbatim, fuite assumée.
_ROUTAGE = frozenset({"name"})
#: Sous-arbres de données libres d'un message JSON-RPC.
_DONNEES = frozenset({"params", "result", "error"})
#: Champs où MCP range une charge encodée.
_CHARGES = ("blob", "data", "content")
#: Borne de la charge DÉTENDUE. Le proxy plafonne ce qu'il LIT à 32 Mio ; la
#: décompression, elle, alloue ce que l'amont décide. Même borne, même raison —
#: ce qui ne tient pas en mémoire ne peut pas être pseudonymisé — mais c'est
#: ici qu'elle manquait, et l'entrée n'en dit rien : 199 Kio de zéros gzipés
#: font 200 Mio en sortie, mesurés.
_MAX_CLAIR = 32 * 1024 * 1024


class BinaryBody(RuntimeError):
    """Ce corps n'est pas du texte : il ne peut être ni relu ni réécrit."""


def _semble_du_texte(clair: str) -> bool:
    """Un binaire COURT peut décoder en UTF-8 par hasard ; le substituer le
    corromprait. Un texte réel ne porte pas d'octet nul et très peu de
    caractères de contrôle — c'est le même discriminant que le walker utilise
    pour choisir un jeu de caractères."""
    if "\x00" in clair:
        return False
    controles = sum(1 for c in clair if c < " " and c not in "\t\n\r")
    return controles * 20 <= len(clair)


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
            body = self._detendre(body)
        try:
            rendu = self._appliquer_clair(body, transformer)
        except RecursionError as exc:
            # `json.loads` est itératif en C et avale une profondeur
            # arbitraire ; la traversée, elle, récurse en Python. Douze kilos
            # d'octets — très en dessous de la limite d'entrée — faisaient
            # sauter la pile, et la connexion mourait sans un mot. Même classe
            # que la bombe gzip : une petite entrée, un coût disproportionné.
            raise BinaryBody(
                "JSON trop profond pour être relu sans épuiser la pile") from exc
        return gzip.compress(rendu) if comprime else rendu

    @staticmethod
    def _detendre(body: bytes) -> bytes:
        """Décompresse en BORNANT la sortie.

        `gzip.decompress` alloue ce que l'amont décide : sur du texte répétitif
        un rapport de 1000:1 est banal, donc les 32 Mio que le proxy accepte en
        entrée peuvent en demander des milliers en sortie. Mesuré avant
        correctif : 199 Kio de charge, 400 Mio alloués, et la limite d'entrée
        n'y voyait rien — c'est la seule borne du chemin qui portait sur la
        mauvaise grandeur.
        """
        moteur = zlib.decompressobj(wbits=31)
        try:
            clair = moteur.decompress(body, _MAX_CLAIR)
        except zlib.error as exc:
            raise BinaryBody(f"corps gzip illisible : {exc}") from exc
        if moteur.unconsumed_tail or moteur.unused_data or not moteur.eof:
            # Détendu au-delà de la borne, ou plusieurs membres gzip : dans les
            # deux cas on ne peut pas rendre le corps entier, et en rendre une
            # partie dirait qu'on l'a lu.
            raise BinaryBody(
                f"corps gzip détendu au-delà de {_MAX_CLAIR} octets, ou en "
                "plusieurs membres : il ne peut pas être relu")
        return clair

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
        rendu = {
            transformer(cle) if cle not in _ROUTAGE else cle:
                valeur if cle in _ROUTAGE else self._libre(valeur, transformer)
            for cle, valeur in noeud.items()
        }
        # `_libre` traverse les charges encodées de ses sous-dicts ; ce
        # niveau-ci n'en faisait rien, et un serveur MCP range le contenu d'une
        # ressource DIRECTEMENT sous `result` aussi souvent que sous un
        # sous-objet. La valeur réelle sortait alors en base64, sans entrée au
        # coffre ni substitut non résolu : rien à compter.
        return self._charge_encodee(noeud, rendu, transformer)

    def _charge_encodee(self, source: dict, rendu: dict, transformer):
        """Traverse une charge base64 qui SE DÉCODE en texte.

        Un serveur MCP range le contenu d'une ressource sous `blob`. Traité
        comme une chaîne opaque, le fichier traversait VERBATIM dans les deux
        sens — la lecture d'une ressource rendait le document brut à l'agent,
        et son écriture le sortait tel quel.

        **Le type MIME déclaré ne décide pas.** Il était la porte d'entrée ;
        or il est écrit par l'amont. Un serveur qui étiquetait `image/png` une
        charge de texte la faisait sortir intacte, et il suffisait de deux
        déclinaisons contradictoires de la clé (`mimeType` et `mimetype`) pour
        choisir celle qui l'arrangeait. Faire dépendre la protection d'une
        valeur écrite par celui dont on se protège est l'anti-pattern du
        projet.

        Ce qui décide est le DÉCODAGE : du base64 qui rend de l'UTF-8 propre
        est du texte, quoi qu'on en déclare. Un binaire échoue au décodage dès
        ses premiers octets ; s'il passe par hasard, `_semble_du_texte`
        l'arrête. Se tromper vers le texte corrompt un binaire, ce qui se VOIT ;
        se tromper vers le binaire laisse sortir une valeur réelle sans laisser
        de trace.
        """
        for champ in _CHARGES:
            valeur = source.get(champ)
            if not isinstance(valeur, str):
                continue
            try:
                clair = base64.b64decode(valeur, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue  # pas du base64 textuel : la chaîne a déjà été traitée
            if not _semble_du_texte(clair):
                continue
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
