"""What the forward proxy does with an MCP body.

JSON-RPC has the same shape as every protocol this project has already been
burnt by: a thin envelope that must stay verbatim, wrapped around free-form
data where a key is as much a value as a value is.

So the rule is the one the walker arrived at after five rounds of getting it
wrong: **a key is protocol by its POSITION, never by its name.** `id` at the
message level routes the response; `id` inside `params` is a customer record.
"""
from __future__ import annotations

import json

import pytest

from anonproxy.forward.jsonrpc import BinaryBody, JsonRpcTransform

REELS = {
    "db-01.acme.internal": "hote-fictif.test",
    "10.1.2.3": "198.18.4.5",
    "acme-billing": "cedar-vault",
}
FICTIFS = {v: k for k, v in REELS.items()}


def _substituer(texte: str) -> str:
    for reel, fictif in REELS.items():
        texte = texte.replace(reel, fictif)
    return texte


def _restaurer(texte: str) -> str:
    for fictif, reel in FICTIFS.items():
        texte = texte.replace(fictif, reel)
    return texte


@pytest.fixture
def transform():
    return JsonRpcTransform(to_surrogate=_substituer, to_real=_restaurer)


def _sortant(transform, message: dict) -> dict:
    return json.loads(transform.outgoing("h", {}, json.dumps(message).encode()))


def test_the_envelope_stays_verbatim(transform):
    """`jsonrpc`, `id` et `method` routent le message. Les substituer casse la
    correspondance requête/réponse et le dispatch du serveur."""
    sortie = _sortant(transform, {
        "jsonrpc": "2.0", "id": "db-01.acme.internal",
        "method": "tools/call", "params": {}})
    assert sortie["jsonrpc"] == "2.0"
    assert sortie["method"] == "tools/call"
    assert sortie["id"] == "db-01.acme.internal", \
        "l'id de corrélation est du protocole, même quand il ressemble à autre chose"


def test_a_real_value_in_the_arguments_is_substituted(transform):
    sortie = _sortant(transform, {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "kubectl", "arguments": {
            "host": "db-01.acme.internal", "ip": "10.1.2.3"}}})
    args = sortie["params"]["arguments"]
    assert args["host"] == "hote-fictif.test"
    assert args["ip"] == "198.18.4.5"


def test_a_key_under_params_is_data_too(transform):
    """La leçon du walker : sous des données libres, une CLÉ porte des valeurs.
    `{"db-01.acme.internal": {...}}` est un nom de paramètre courant."""
    sortie = _sortant(transform, {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"arguments": {"db-01.acme.internal": {"état": "ok"}}}})
    assert "hote-fictif.test" in sortie["params"]["arguments"]
    assert "db-01.acme.internal" not in json.dumps(sortie)


def test_the_tool_name_stays_verbatim(transform):
    """`params.name` est la clé de routage du serveur MCP : la substituer
    casse l'appel en silence. Même arbitrage que `tools[].name` côté walker,
    et même fuite assumée — c'est une convention de nommage, pas une valeur."""
    sortie = _sortant(transform, {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "acme-billing", "arguments": {}}})
    assert sortie["params"]["name"] == "acme-billing"


def test_the_result_comes_back_restored(transform):
    """Sens entrant : l'opérateur doit voir le réel, pas le substitut."""
    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"hôte": "hote-fictif.test"}}).encode()
    rendu = json.loads(transform.incoming("h", {}, corps))
    assert rendu["result"]["hôte"] == "db-01.acme.internal"


def test_a_round_trip_restores_what_it_substituted(transform):
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"arguments": {"cible": "db-01.acme.internal"}}}
    sortant = transform.outgoing("h", {}, json.dumps(message).encode())
    assert b"db-01.acme.internal" not in sortant
    assert json.loads(transform.incoming("h", {}, sortant)) == message


def test_a_batch_is_a_list_of_messages(transform):
    """JSON-RPC autorise un lot. Ne traiter que l'objet racine laisserait
    passer tout un lot en clair."""
    lot = [{"jsonrpc": "2.0", "id": 1, "method": "a",
            "params": {"h": "db-01.acme.internal"}},
           {"jsonrpc": "2.0", "id": 2, "method": "b",
            "params": {"h": "10.1.2.3"}}]
    sortie = json.loads(transform.outgoing("h", {}, json.dumps(lot).encode()))
    assert [m["params"]["h"] for m in sortie] == ["hote-fictif.test", "198.18.4.5"]


def test_a_body_that_is_not_json_is_treated_as_text(transform):
    """Une destination inspectée ne sert pas que du JSON-RPC. Un texte qui n'en
    est pas doit être protégé quand même, pas rendu tel quel."""
    corps = b"GET /metrics from db-01.acme.internal"
    assert transform.outgoing("h", {}, corps) == \
        b"GET /metrics from hote-fictif.test"


def test_invalid_json_does_not_crash_the_channel(transform):
    """Un corps tronqué ne doit pas tuer la connexion : il est traité comme du
    texte, donc protégé, ce qui est le sens sûr."""
    corps = b'{"params": {"h": "db-01.acme.internal"'
    assert b"db-01.acme.internal" not in transform.outgoing("h", {}, corps)


def test_a_binary_body_is_refused_rather_than_relayed(transform):
    """Sur une destination déclarée À INSPECTER, relayer ce qu'on ne sait pas
    lire dirait que ça a été lu. Le proxy en fait un refus."""
    with pytest.raises(BinaryBody):
        transform.outgoing("h", {}, b"\x89PNG\r\n\x1a\n\x00\xff\xfe")


def test_an_empty_body_is_left_alone(transform):
    assert transform.outgoing("h", {}, b"") == b""


# --------------------------------------------------------------------------- #
# Tour 6-7 — ce qu'un corps encodé transporte
# --------------------------------------------------------------------------- #


def test_a_textual_payload_hidden_in_base64_is_still_protected(transform):
    """Le walker Anthropic décode déjà le base64 quand le type MIME est
    textuel (round 12). La logique n'était pas répliquée ici : une lecture de
    ressource MCP transportait le fichier VERBATIM, encodé, dans les deux
    sens."""
    import base64

    charge = base64.b64encode(
        b"log: connect to db-01.acme.internal on 5432").decode()
    corps = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "resources/read",
        "params": {"arguments": {"mimeType": "text/plain", "blob": charge}}}
    ).encode()
    rendu = json.loads(transform.outgoing("h", {}, corps))
    dedans = base64.b64decode(rendu["params"]["arguments"]["blob"]).decode()
    assert "db-01.acme.internal" not in dedans, dedans
    assert "hote-fictif.test" in dedans


def test_a_binary_payload_is_left_alone(transform):
    """Décoder, substituer et ré-encoder un PNG le CORRIGE. Seul un type MIME
    textuel autorise la traversée — même arbitrage que le walker."""
    import base64

    png = base64.b64encode(b"\x89PNG\r\n\x1a\n\x00\xff\xfe").decode()
    corps = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "x",
        "params": {"arguments": {"mimeType": "image/png", "blob": png}}}).encode()
    rendu = json.loads(transform.outgoing("h", {}, corps))
    assert rendu["params"]["arguments"]["blob"] == png


def test_a_nested_batch_does_not_forge_an_envelope(transform):
    """JSON-RPC autorise UN niveau de lot. En descendant plus loin, tout dict
    interne recevait le traitement d'enveloppe — `id` et `method` verbatim,
    alors que ce sont des données à cette profondeur. Même motif que les
    rounds 4, 6, 10 et 11 : une sémantique de protocole propagée au-delà de sa
    portée."""
    lot = [[{"jsonrpc": "2.0", "id": "db-01.acme.internal", "method": "x",
             "params": {}}]]
    rendu = json.loads(transform.outgoing("h", {}, json.dumps(lot).encode()))
    assert "db-01.acme.internal" not in json.dumps(rendu)


def test_a_gzipped_body_is_read_instead_of_killing_the_connection(transform):
    """`BinaryBody` n'est pas rattrapée par l'échange : la connexion mourait
    sans 502. Un corps gzipé est du texte, il suffit de le détendre."""
    import gzip

    clair = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"hote": "db-01.acme.internal"}}).encode()
    sortie = transform.outgoing("h", {"content-encoding": "gzip"},
                                gzip.compress(clair))
    assert b"db-01.acme.internal" not in gzip.decompress(sortie)
    assert b"hote-fictif.test" in gzip.decompress(sortie)
