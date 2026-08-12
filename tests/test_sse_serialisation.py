"""Le flux SSE sérialise comme les deux autres chemins, ou il meurt en silence.

Un demi-substitut Unicode (`"\\ud800"`) est du JSON VALIDE et n'est PAS de
l'UTF-8 valide. Le corps non streamé et le canal MCP l'ont appris ; le flux SSE
était la TROISIÈME implantation de la même règle, et la seule oubliée — alors
que le commit qui posait les deux autres énonçait déjà que trois implantations
d'une règle sont le défaut jumeau que ce projet paie le plus souvent.

Ce qui rend ce chemin-ci pire que les autres : l'échec ne coûte pas un
événement mais le FLUX ENTIER. Tous ceux qui suivent le toxique sont jetés,
`message_stop` compris, donc le client attend sans fin.
"""
from __future__ import annotations

import json

import pytest

from anonproxy.sse import encode_sse


def _charge(rendu: bytes) -> dict:
    return json.loads(rendu.split(b"\ndata: ", 1)[1].rstrip(b"\n"))


@pytest.mark.parametrize("texte", ["a\ud800b", "\udfff", "début\ud800fin"])
def test_un_demi_substitut_ne_tue_pas_le_flux(texte):
    rendu = encode_sse({"type": "content_block_delta",
                        "delta": {"type": "text_delta", "text": texte}})
    assert rendu.startswith(b"event: content_block_delta\n")
    assert _charge(rendu)["delta"]["text"] == texte


def test_la_forme_compacte_et_l_utf8_sont_preserves():
    """L'AUTRE MOITIÉ : le repli ne doit s'appliquer que là où il est
    nécessaire. Un accent reste de l'UTF-8 sur le fil, et la sérialisation
    reste compacte — Anthropic la produit ainsi."""
    rendu = encode_sse({"type": "x", "t": "café"})
    assert b"caf\xc3\xa9" in rendu, rendu
    assert b'": "' not in rendu, "la forme compacte est perdue"


def test_le_type_reste_lisible_meme_s_il_n_est_pas_une_chaine():
    """Un amont hostile peut mettre n'importe quoi dans `type` ; l'en-tête de
    l'événement doit rester encodable."""
    assert encode_sse({"type": {"a": 1}}).startswith(b"event: {'a': 1}\n")
