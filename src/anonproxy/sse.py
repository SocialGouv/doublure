"""Encodage/décodage du flux SSE Anthropic.

Le walker fourni travaille sur des événements déjà désérialisés ; ce module
fait la traduction octets ⇄ dict, et rien d'autre.
"""
from __future__ import annotations

import json
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
    etype = event.get("type", "message")
    data = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    return f"event: {etype}\ndata: {data}\n\n".encode("utf-8")


#: Séparateur de blocs SSE : DEUX fins de ligne consécutives, chacune pouvant
#: être ``\r\n``, ``\r`` ou ``\n`` (RFC EventSource) — y compris mélangées.
#: Énumérer les combinaisons en ratait la moitié, et un flux non reconnu ne
#: rend AUCUN bloc : le tampon grossit sans fin, l'opérateur ne voit rien
#: passer, et aucune erreur ne remonte.
#: Le groupe est ATOMIQUE : sans lui, la répétition rétro-traque et consomme un
#: simple ``\r\n`` comme DEUX fins de ligne — chaque ligne deviendrait un bloc.
_SEPARATEUR_BLOC = re.compile(r"(?>\r\n|\r|\n){2}")


def iter_blocks(chunk: str, buffer: str) -> tuple[list[str], str]:
    """Découpe un flux SSE en blocs complets. Retourne (blocs, reste tamponné)."""
    buffer += chunk
    blocks: list[str] = []
    while (found := _SEPARATEUR_BLOC.search(buffer)):
        blocks.append(buffer[:found.start()])
        buffer = buffer[found.end():]
    return blocks, buffer


