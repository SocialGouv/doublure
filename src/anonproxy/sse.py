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


def parse_sse_block(block: str) -> dict[str, Any] | None:
    """Extrait le JSON d'un bloc SSE (``event:`` + ``data:``).

    Retourne ``None`` pour les blocs sans données exploitables (commentaires
    de keep-alive, ``data: [DONE]``).
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
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


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


