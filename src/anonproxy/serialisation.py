"""Rendre du JSON qu'un demi-substitut Unicode ne tue pas.

`"\\ud800"` est du JSON VALIDE et n'est PAS de l'UTF-8 valide : `json.loads`
l'accepte, `json.dumps(...).encode("utf-8")` le refuse. Un serveur MCP en
produit exprès aussi bien qu'un export UTF-16 ou un texte CJK mal encodé en
produit par accident, et l'échange mourait alors sur une exception non nommée.

Ce module existe pour qu'il n'y ait qu'UN endroit où cette décision est prise.
Elle avait déjà été rendue dans le coffre au tour 12 — *une valeur traverse la
chaîne entière ou n'y entre nulle part* — et il a fallu la reprendre dans le
canal MCP, puis dans le proxy inverse : trois implantations d'une même règle,
c'est la définition du défaut jumeau que ce projet a payé le plus souvent.

Ce qui est rendu est la forme que l'ÉMETTEUR a lui-même employée, `\\ud800`,
donc de l'UTF-8 valide, et `json.loads` en retrouve exactement la même valeur.
`errors="surrogatepass"` mettrait à la place du WTF-8 sur le fil, que le
destinataire n'a aucune raison d'accepter.
"""
from __future__ import annotations

import json


def dumps_utf8(valeur) -> bytes:
    """Le JSON de `valeur`, toujours encodable, sans rien perdre."""
    try:
        return json.dumps(valeur, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        return json.dumps(valeur, ensure_ascii=True).encode("utf-8")
