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


#: Séparateur de blocs SSE. Les trois formes sont valides (RFC EventSource) :
#: ne chercher que ``\n\n`` sur un flux en CRLF ne rend AUCUN bloc — le tampon
#: grossit sans fin et l'opérateur ne voit rien passer, sans la moindre erreur.
_SEPARATEUR_BLOC = re.compile(r"\r\n\r\n|\r\r|\n\n")


def iter_blocks(chunk: str, buffer: str) -> tuple[list[str], str]:
    """Découpe un flux SSE en blocs complets. Retourne (blocs, reste tamponné)."""
    buffer += chunk
    blocks: list[str] = []
    while (found := _SEPARATEUR_BLOC.search(buffer)):
        blocks.append(buffer[:found.start()])
        buffer = buffer[found.end():]
    return blocks, buffer


