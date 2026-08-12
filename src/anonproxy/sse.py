"""Encodage/décodage du flux SSE Anthropic.

Le walker fourni travaille sur des événements déjà désérialisés ; ce module
fait la traduction octets ⇄ dict, et rien d'autre.
"""
from __future__ import annotations

import json

from anonproxy.serialisation import dumps_utf8
import re
from typing import Any


#: Fin de LIGNE au sens SSE. Voir le commentaire de `parse_sse_block`.
_LIGNE = re.compile(r"\r\n|\r|\n")


class BlocSSEIllisible(RuntimeError):
    """Ce bloc porte des donnees, et elles ne se parsent pas."""


def parse_sse_block(block: str) -> dict[str, Any] | None:
    """Extrait le JSON d'un bloc SSE (``event:`` + ``data:``).

    Retourne ``None`` pour les blocs sans données exploitables (commentaires
    de keep-alive, ``data: [DONE]``), et lève `BlocSSEIllisible` quand il y a
    des données que l'on ne sait pas lire — deux situations que le même `None`
    confondait, la seconde partant alors verbatim sous un commentaire qui
    annonçait un ping.
    """
    # Le découpage en LIGNES suit la spec SSE — `\r\n`, `\r`, `\n` — et rien
    # d'autre. `str.splitlines` coupe AUSSI sur U+2028, U+2029, U+0085 et les
    # séparateurs de fichier : le séparateur de BLOCS, lui, ne les reconnaît
    # pas. Un `U+2028` dans un texte — que `json.dumps` n'échappe pas hors mode
    # ASCII — faisait donc échouer le parsage, et un bloc non parsé part
    # VERBATIM : ses substituts ne sont jamais restaurés, et l'opérateur lit un
    # nom fictif sans rien pour le lui dire.
    data_lines = [
        line[5:].lstrip() for line in _LIGNE.split(block) if line.startswith("data:")
    ]
    if not data_lines:
        return None
    payload = "\n".join(data_lines).strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        lu = json.loads(payload)
    except json.JSONDecodeError as exc:
        # `None` disait DEUX choses : « rien a faire » (ping, commentaire,
        # `[DONE]`) et « il y a des donnees, je ne sais pas les lire ». Le
        # second part alors VERBATIM, donc ses substituts ne sont jamais
        # restaures et l'operateur lit un nom fictif — un fail-open silencieux
        # dans le sens du retour, sous un commentaire qui annoncait un ping.
        raise BlocSSEIllisible(
            f"bloc SSE porteur de {len(payload)} octets de donnees illisibles"
        ) from exc
    if not isinstance(lu, dict):
        # Le type de retour annonce un dict, et il ne le tenait pas : `true`,
        # `42`, une liste ou une chaine sont du JSON parfaitement valide, et le
        # reecriveur leve alors `AttributeError` sur `event.get`. L'exception
        # est rattrapee au niveau de la BOUCLE, donc le flux s'arrete la — tous
        # les evenements suivants perdus, `message_stop` compris, et le client
        # attend sans fin. Un contrat qu'on annonce se tient.
        raise BlocSSEIllisible(
            f"bloc SSE dont la charge est un {type(lu).__name__}, pas un objet")
    return lu


def encode_sse(event: dict[str, Any]) -> bytes:
    """Sérialise un événement au format SSE Anthropic (``event:`` + ``data:``)."""
    # Les DEUX moitiés — le nom et la charge — passent par le même encodeur. Un
    # demi-substitut Unicode y faisait lever l'encodage, et ici l'échec ne coûte
    # pas un événement mais le FLUX : le générateur émet une erreur et rend la
    # main, donc tout ce qui suit est perdu, `message_stop` compris, et le
    # client attend sans fin. Router la charge et laisser le nom sur
    # `str.encode` a reproduit le défaut dans la même fonction, une ligne plus
    # haut. `dumps_utf8` rend une chaîne JSON dont on retire les guillemets : un
    # nom ordinaire, accents compris, ressort octet pour octet, et un `\n` ou un
    # `\r` glissé dedans est échappé au lieu de couper le bloc en deux.
    etype = dumps_utf8(str(event.get("type", "message")))[1:-1]
    return (b"event: " + etype + b"\ndata: "
            + dumps_utf8(event, separators=(",", ":")) + b"\n\n")


#: Séparateur de blocs SSE : DEUX fins de ligne consécutives, chacune pouvant
#: être ``\r\n``, ``\r`` ou ``\n`` (RFC EventSource) — y compris mélangées.
#: Énumérer les combinaisons en ratait la moitié, et un flux non reconnu ne
#: rend AUCUN bloc : le tampon grossit sans fin, l'opérateur ne voit rien
#: passer, et aucune erreur ne remonte.
#: Le groupe est ATOMIQUE : sans lui, la répétition rétro-traque et consomme un
#: simple ``\r\n`` comme DEUX fins de ligne — chaque ligne deviendrait un bloc.
_SEPARATEUR_BLOC = re.compile(r"(?>\r\n|\r|\n){2}")


#: Aucun événement SSE légitime n'approche cette taille. Un amont qui n'émet
#: jamais de séparateur ferait sinon croître le tampon sans fin.
MAX_TAMPON = 16 * 1024 * 1024


class FluxSSEInvalide(RuntimeError):
    """Le flux amont ne ressemble pas à du SSE : on refuse de l'accumuler."""


def iter_blocks(chunk: str, buffer: str) -> tuple[list[str], str]:
    """Découpe un flux SSE en blocs complets. Retourne (blocs, reste tamponné)."""
    buffer += chunk
    blocks: list[str] = []
    while (found := _SEPARATEUR_BLOC.search(buffer)):
        blocks.append(buffer[:found.start()])
        buffer = buffer[found.end():]
    # Une coupure de chunk au milieu d'un `\r\n` peut laisser un `\n` en tête
    # du bloc suivant. Sans effet : `parse_sse_block` ne retient que les lignes
    # commençant par `data:`. Retenir le `\r` en attendant la suite perdrait,
    # lui, le dernier bloc d'un flux qui se termine par `\r\r`.
    if len(buffer) > MAX_TAMPON:
        raise FluxSSEInvalide(
            f"aucun séparateur SSE après {len(buffer)} octets : flux amont "
            "invalide, on refuse de continuer à accumuler"
        )
    return blocks, buffer


