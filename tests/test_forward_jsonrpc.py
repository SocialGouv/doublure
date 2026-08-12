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


def test_a_gzip_bomb_is_refused_instead_of_allocated(transform):
    """HAUT. `_lire_corps` plafonne ce que le proxy LIT à 32 Mio ; la
    décompression, elle, allouait ce que l'amont décidait.

    Mesuré avant correctif : 199 Kio de zéros gzipés — très en dessous de la
    limite d'entrée — faisaient 400 Mio de mémoire, et la même charge portée à
    la limite d'entrée en aurait demandé des milliers de fois plus. La seule
    borne du chemin portait sur la mauvaise grandeur.
    """
    import gzip

    bombe = gzip.compress(b"\x00" * (48 * 1024 * 1024))
    assert len(bombe) < 1024 * 1024, "la charge doit tenir sous la limite d'entrée"
    with pytest.raises(BinaryBody, match="détendu au-delà"):
        transform.incoming("h", {"content-encoding": "gzip"}, bombe)


def test_a_body_just_under_the_bound_still_goes_through(transform):
    """L'AUTRE MOITIÉ : borner ne doit pas casser un corps gzipé ordinaire."""
    import gzip

    clair = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"hote": "db-01.acme.internal",
                                   "bourrage": "x" * 100_000}}).encode()
    sortie = transform.outgoing("h", {"content-encoding": "gzip"},
                                gzip.compress(clair))
    assert b"hote-fictif.test" in gzip.decompress(sortie)


# --------------------------------------------------------------------------- #
# Tour 10 — ce qui décide qu'une charge est du texte, et ce qui la borne
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cle", ["params", "result", "error"])
def test_a_payload_at_the_first_level_is_traversed_too(transform, cle):
    """CRITIQUE, fuite SILENCIEUSE. Le décodage des charges encodées vivait
    dans `_libre`, qui traite les sous-dicts ; le PREMIER niveau sous
    `params`/`result`/`error` a son propre chemin, et il n'en faisait rien.

    Un serveur MCP range le contenu d'une ressource directement sous `result`
    aussi souvent que sous un sous-objet. La valeur réelle sortait alors en
    base64 : pas d'entrée au coffre, pas de substitut non résolu, rien à
    compter. Mon test d'origine plaçait la charge dans `params.arguments` —
    c'est-à-dire dans la moitié qui marchait."""
    import base64

    charge = base64.b64encode(b"log: db-01.acme.internal").decode()
    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        cle: {"mimeType": "text/plain", "blob": charge}}).encode()
    rendu = json.loads(transform.outgoing("h", {}, corps))
    dedans = base64.b64decode(rendu[cle]["blob"]).decode()
    assert "db-01.acme.internal" not in dedans, dedans
    assert "hote-fictif.test" in dedans


@pytest.mark.parametrize("types", [
    {"mimeType": "image/png"},                          # étiquette mensongère
    {"mimeType": "image/png", "mimetype": "text/plain"},  # deux, contradictoires
    {"mimeType": "application/vnd.acme+json"},          # RFC 6839, structuré
    {},                                                 # aucune étiquette
])
def test_the_declared_media_type_does_not_decide(transform, types):
    """CRITIQUE. Le type MIME était la porte d'entrée du décodage — or il est
    écrit par l'AMONT. Étiqueter `image/png` une charge de texte la faisait
    sortir intacte, et deux déclinaisons contradictoires de la clé suffisaient
    à choisir celle qui arrange.

    Faire dépendre la protection d'une valeur écrite par celui dont on se
    protège est l'anti-pattern du projet. C'est le DÉCODAGE qui décide."""
    import base64

    charge = base64.b64encode(b"db-01.acme.internal").decode()
    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {**types, "blob": charge}}).encode()
    rendu = json.loads(transform.outgoing("h", {}, corps))
    assert base64.b64decode(rendu["result"]["blob"]).decode() == "hote-fictif.test"


def test_a_real_binary_is_still_left_intact(transform):
    """L'AUTRE MOITIÉ : décider par le décodage ne doit pas corrompre un vrai
    binaire. Il échoue en UTF-8 dès ses premiers octets ; s'il passait par
    hasard, ses octets nuls l'arrêtent."""
    import base64

    png = base64.b64encode(b"\x89PNG\r\n\x1a\n\x00\xff\xfe" * 20).decode()
    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"mimeType": "image/png", "blob": png}}).encode()
    rendu = json.loads(transform.outgoing("h", {}, corps))
    assert rendu["result"]["blob"] == png


def test_a_deeply_nested_body_is_refused_instead_of_killing_the_stack(transform):
    """HAUT. `json.loads` est itératif en C et avale une profondeur arbitraire ;
    la traversée, elle, récurse en Python. Douze kilo-octets — très en dessous
    de la limite d'entrée de 32 Mio — faisaient sauter la pile, et la connexion
    mourait sans un mot. Même classe que la bombe gzip : une petite entrée, un
    coût disproportionné."""
    profond = ('{"a":' * 2000) + "1" + ("}" * 2000)
    assert len(profond) < 20_000
    with pytest.raises(BinaryBody, match="trop profond"):
        transform.outgoing("h", {}, profond.encode())


@pytest.mark.parametrize("suffixe,nom", [
    (b"\x00", "un octet nul"),
    (b"\x01\x02", "deux octets de contrôle"),
    (bytes(range(1, 32)), "trente-et-un octets de contrôle"),
])
def test_no_shape_guard_can_switch_the_substitution_off(transform, suffixe, nom):
    """CRITIQUE. Le garde-fou « est-ce que ça ressemble à du texte ? » que
    j'avais ajouté — refus sur un octet nul ou plus de 5 % de contrôles — était
    lui-même la fuite : l'amont glissait UN octet nul et la substitution
    disparaissait. Silencieuse, comme toujours dans cette classe.

    Son propre commentaire énonçait la règle qu'il violait : se tromper vers le
    binaire laisse sortir SANS TRACE, se tromper vers le texte corrompt
    VISIBLEMENT. Un garde-fou dont l'échec est silencieux et que l'attaquant
    déclenche à volonté n'en est pas un.

    Ce test vise le MÉCANISME et pas les trois formes : toute garde ajoutée
    par-dessus le décodage le rouvrirait."""
    import base64

    charge = base64.b64encode(b"db-01.acme.internal" + suffixe).decode()
    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "params": {"blob": charge}}).encode()
    rendu = json.loads(transform.outgoing("h", {}, corps))
    sorti = base64.b64decode(rendu["params"]["blob"])
    assert b"db-01.acme.internal" not in sorti, f"{nom} : {sorti!r}"
    assert b"hote-fictif.test" in sorti, sorti


@pytest.mark.parametrize("sens", ["incoming", "outgoing"])
def test_two_keys_converging_never_lose_a_pair(transform, sens):
    """HAUT, perte SILENCIEUSE, dans les DEUX sens. Deux clés distinctes qui
    convergent après transformation : la seconde écrasait la première et une
    valeur disparaissait du message, sans exception ni compteur.

    Au retour, c'est ce que le serveur MCP a réellement répondu qui n'arrive
    jamais à l'opérateur — sur le canal que ce module existe pour protéger. Le
    walker Anthropic avait ce garde ; celui-ci ne l'avait pas. Un résidu
    accepté se compte, une perte de donnée se refuse."""
    t = JsonRpcTransform(to_surrogate=lambda s: "meme" if s == "cle_a" else s,
                         to_real=lambda s: "meme" if s == "cle_a" else s)
    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"cle_a": "perdue", "meme": "gardée"}}).encode()
    with pytest.raises(BinaryBody, match="collision de clés"):
        getattr(t, sens)("h", {}, corps)


def test_the_same_collision_is_caught_at_any_depth(transform):
    """`_libre` récurse : le garde doit valoir à chaque niveau, pas seulement
    au premier."""
    t = JsonRpcTransform(to_surrogate=lambda s: "meme" if s == "cle_a" else s,
                         to_real=lambda s: s)
    corps = json.dumps({"jsonrpc": "2.0", "id": 1, "params": {"arguments": {
        "profond": {"cle_a": "perdue", "meme": "gardée"}}}}).encode()
    with pytest.raises(BinaryBody, match="collision de clés"):
        t.outgoing("h", {}, corps)
