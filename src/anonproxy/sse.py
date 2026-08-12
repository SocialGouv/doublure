"""Encodage/décodage du flux SSE Anthropic.

Le walker fourni travaille sur des événements déjà désérialisés ; ce module
fait la traduction octets ⇄ dict, et rien d'autre.
"""
from __future__ import annotations

import json

from anonproxy.serialisation import dumps_utf8
import re
from typing import Any


def parse_sse_block(block: str) -> dict[str, Any] | None:
    """Extrait le JSON d'un bloc SSE (``event:`` + ``data:``).

    Retourne ``None`` pour les blocs sans données exploitables (commentaires
    de keep-alive, ``data: [DONE]``).
    """
    data_lines = [
        line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")
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
    # La sérialisation passe par `dumps_utf8`, comme les deux autres chemins :
    # un demi-substitut Unicode y faisait lever l'encodeur, et le flux mourait
    # sur un événement `error` — tous les événements SUIVANTS jetés, y compris
    # `message_stop`, donc un client qui attend sans fin. Troisième implantation
    # d'une même règle, et la seule qui ne l'avait pas héritée.
    etype = str(event.get("type", "message"))
    return (b"event: " + etype.encode("utf-8") + b"\ndata: "
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
    # du bloc suivant. `parse_sse_block` s'appuie sur `splitlines`, qui ignore
    # une ligne vide : sans effet. Retenir le `\r` en attendant la suite
    # perdrait, lui, le dernier bloc d'un flux qui se termine par `\r\r`.
    if len(buffer) > MAX_TAMPON:
        raise FluxSSEInvalide(
            f"aucun séparateur SSE après {len(buffer)} octets : flux amont "
            "invalide, on refuse de continuer à accumuler"
        )
    return blocks, buffer


