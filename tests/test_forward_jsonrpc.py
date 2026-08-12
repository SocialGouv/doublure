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


@pytest.mark.parametrize("champ", [
    "blob", "payload", "attachment", "text", "value", "raw", "b64", "chunk",
])
def test_the_field_name_does_not_decide_either(transform, champ):
    """CRITIQUE. Après le type MIME, la LISTE DE NOMS DE CHAMPS — écrite elle
    aussi par l'amont. Il suffisait de ranger la charge sous `payload` au lieu
    de `blob` pour que la protection tombe. Deux versions de la même erreur, au
    même endroit, à deux heures d'intervalle.

    Balayer toutes les chaînes est sans danger parce que le tour est
    l'IDENTITÉ quand rien n'est détecté."""
    import base64

    charge = base64.b64encode(b"connect db-01.acme.internal").decode()
    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {champ: charge}}).encode()
    rendu = json.loads(transform.outgoing("h", {}, corps))
    dedans = base64.b64decode(rendu["result"][champ]).decode()
    assert "db-01.acme.internal" not in dedans, dedans
    assert "hote-fictif.test" in dedans


@pytest.mark.parametrize("opaque", [
    "ZGVzIG9jdGV0cyBzYW5zIHJpZW4gZGVkYW5z",              # base64 de texte neutre
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijkl",  # JWT (base64url)
    "a3f5c9e1b7d2486a3f5c9e1b7d2486a3",                   # hexadécimal
    "sk-proj-AAAABBBBCCCCDDDDEEEEFFFF",                   # jeton à préfixe
])
def test_an_opaque_string_comes_back_byte_for_byte(transform, opaque):
    """L'AUTRE MOITIÉ, et c'est elle qui rend le balayage acceptable : ce qui
    ne contient rien à substituer doit ressortir IDENTIQUE. Décoder puis
    ré-encoder du base64 canonique est l'identité ; l'alphabet standard exclut
    le base64url, donc les parties d'un JWT ne sont pas touchées."""
    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"v": opaque}}).encode()
    rendu = json.loads(transform.outgoing("h", {}, corps))
    assert rendu["result"]["v"] == opaque


@pytest.mark.parametrize("reel", ["10.0.0.1", "srv-42", "db01", "1.1.1.1"])
def test_no_length_threshold_can_switch_the_substitution_off(reel):
    """CRITIQUE, et c'est le TROISIÈME garde-fou à échec silencieux du même
    fichier en trois heures — tous les miens.

    J'avais posé une longueur minimale (16 caractères) « parce qu'en dessous ce
    n'est pas une charge ». `10.0.0.1` s'encode en douze caractères, `srv-42`
    en huit : toute IPv4 et tout nom d'hôte court passaient intacts. Et c'était
    une RÉGRESSION — les champs historiquement décodés l'étaient sans borne.

    Le motif se répète : une garde posée « par prudence » au-dessus d'une
    décision de protection penche du mauvais côté de l'asymétrie, et c'est
    l'émetteur qui choisit de la déclencher."""
    import base64

    t = JsonRpcTransform(to_surrogate=lambda s: s.replace(reel, "SUBSTITUÉ"),
                         to_real=lambda s: s)
    charge = base64.b64encode(reel.encode()).decode()
    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"blob": charge}}).encode()
    rendu = json.loads(t.outgoing("h", {}, corps))
    assert base64.b64decode(rendu["result"]["blob"]).decode() == "SUBSTITUÉ"


@pytest.mark.parametrize("court", ["dGVzdA==", "QUJDRA==", "eyJhIjoxfQ=="])
def test_a_short_opaque_token_still_comes_back_identical(transform, court):
    """L'AUTRE MOITIÉ : retirer le seuil ne doit pas abîmer un jeton court qui
    décoderait en UTF-8 par accident. Le tour reste l'identité."""
    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"v": court}}).encode()
    rendu = json.loads(transform.outgoing("h", {}, corps))
    assert rendu["result"]["v"] == court


def test_a_payload_inside_a_list_is_traversed(transform):
    """CRITIQUE, fuite SILENCIEUSE. La traversée des charges encodées ne vivait
    que dans la branche DICT : une charge rangée dans une LISTE —
    `{"blobs": ["<base64>"]}`, la forme la plus banale d'un lot de ressources
    MCP — sortait en clair, à toute profondeur."""
    import base64

    charge = base64.b64encode(b"log db-01.acme.internal").decode()
    for corps, chemin in (({"blobs": [charge]}, lambda d: d["blobs"][0]),
                          ({"a": {"b": [[charge]]}}, lambda d: d["a"]["b"][0][0])):
        rendu = json.loads(transform.outgoing("h", {}, json.dumps(
            {"jsonrpc": "2.0", "id": 1, "result": corps}).encode()))
        dedans = base64.b64decode(chemin(rendu["result"])).decode()
        assert "db-01.acme.internal" not in dedans, dedans


def test_mime_wrapped_base64_is_traversed(transform):
    """CRITIQUE. `base64.encodebytes` coupe en lignes de 76, `openssl base64`
    en lignes de 64 — deux producteurs parfaitement standards. La chaîne ne
    correspondait à rien à cause des retours à la ligne, donc sortait
    VERBATIM."""
    import base64

    charge = base64.encodebytes(b"log db-01.acme.internal " * 6).decode()
    rendu = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"blob": charge}}).encode()))
    dedans = base64.b64decode(
        "".join(rendu["result"]["blob"].split())).decode()
    assert "db-01.acme.internal" not in dedans, dedans


@pytest.mark.parametrize("non_canonique", ["SGVsbG9=", "AAAAAR==", "QUJDREVGRw9="])
def test_a_non_canonical_padding_is_left_untouched(transform, non_canonique):
    """La propriété d'IDENTITÉ vaut aussi pour un bourrage non canonique.

    `b64decode(validate=True)` ne valide que l'ALPHABET : des bits de bourrage
    non nuls se décodent, et les ré-encoder les NORMALISERAIT. C'est `_chaine`
    qui tient l'identité — quand la substitution ne change rien, il rend la
    chaîne D'ORIGINE — et non un contrôle de canonicité, qui serait un
    interrupteur (cf. le test suivant)."""
    rendu = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"v": non_canonique}}).encode()))
    assert rendu["result"]["v"] == non_canonique


@pytest.mark.parametrize("reel,prefixe", [("db-01.acme.internal", ""),
                                          ("10.1.2.3", ""),
                                          ("acme-billing", "log ")])
def test_no_padding_bit_can_switch_the_substitution_off(transform, reel, prefixe):
    """CRITIQUE — le contrôle de canonicité était un INTERRUPTEUR de plus.

    Il avait été posé pour préserver un jeton opaque ; il suffisait d'allumer
    un bit de bourrage pour que la charge cesse d'être vue, et la valeur réelle
    sortait sans trace — aucune entrée au coffre, aucun substitut non résolu.
    Tout décodeur du monde réel est permissif sur ces bits : le tiers reçoit
    bien la valeur. Quatrième occurrence, dans ce fichier, du garde-fou ajouté
    au-dessus d'une décision de protection et qui l'éteint.
    """
    import base64

    alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz0123456789+/")
    charge = f"{prefixe}{reel}"
    canonique = base64.b64encode(charge.encode()).decode()
    assert canonique.endswith("="), \
        "sans bourrage il n'y a pas de bit à allumer : le cas ne prouve rien"
    i = canonique.index("=") - 1
    mute = (canonique[:i]
            + alphabet[(alphabet.index(canonique[i]) + 1) % 64]
            + canonique[i + 1:])
    assert mute != canonique
    # Le récepteur tiers, lui, décode : les deux formes portent la même valeur.
    assert base64.b64decode(mute).decode() == charge

    rendu = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"v": mute}}).encode()))
    assert rendu["result"]["v"] != mute, "la charge n'a pas été vue"
    assert reel not in base64.b64decode(rendu["result"]["v"]).decode()


@pytest.mark.parametrize("invisible,nom", [
    ("​", "espace de largeur nulle"),
    ("﻿", "marque d'ordre des octets"),
    ("­", "trait d'union conditionnel"),
    ("⁠", "gluon de mots"),
    ("‍", "liant sans chasse"),
    ("᠎", "séparateur de voyelle mongol"),
])
@pytest.mark.parametrize("sens", ["outgoing", "incoming"])
def test_no_invisible_character_can_switch_the_substitution_off(
        transform, invisible, nom, sens):
    """CRITIQUE — la protection reposait sur une lecture PLUS ÉTROITE que celle
    du destinataire.

    Seuls les BLANCS étaient retirés avant de reconnaître une charge, alors
    qu'un décodeur permissif jette TOUT ce qui n'est pas de l'alphabet. Un
    caractère invisible glissé au milieu suffisait donc à ce que la charge perde
    la forme ici et sorte VERBATIM — sans entrée au coffre, sans substitut non
    résolu, rien à compter — pendant que le récepteur en tirait la valeur
    entière. Mesuré sur `Buffer.from` de Node, qui est l'implémentation MCP
    ordinaire, et sur le décodeur Python appliqué aux octets du fil ; le
    décodeur strict de Go refuse mais rend le préfixe déjà décodé.

    C'est la JUMELLE du retrait des blancs : la moitié visible de la classe
    était traitée, l'autre était l'interrupteur.
    """
    import base64

    reel, fictif = "db-01.acme.internal", "hote-fictif.test"
    source, cible = (reel, fictif) if sens == "outgoing" else (fictif, reel)
    canonique = base64.b64encode(source.encode()).decode()
    piege = canonique[:14] + invisible + canonique[14:]

    # Le récepteur, lui, jette l'invisible et retrouve la valeur entière.
    assert base64.b64decode(piege.encode("utf-8")).decode() == source

    corps = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"v": piege}}).encode()
    rendu = json.loads(getattr(transform, sens)("h", {}, corps))["result"]["v"]
    assert rendu != piege, f"charge non vue ({nom})"
    dedans = base64.b64decode(rendu.encode("utf-8")).decode()
    assert source not in dedans, dedans
    assert cible in dedans, dedans


def _jwt(charge: dict) -> str:
    import base64

    def b64u(donnees):
        return base64.urlsafe_b64encode(donnees).decode().rstrip("=")

    return ".".join([b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()),
                     b64u(json.dumps(charge).encode()),
                     b64u(bytes(range(32)))])


def test_a_jwt_that_carries_nothing_real_comes_out_intact(transform):
    """L'AUTRE MOITIÉ de la règle élargie : elle retire plus de caractères, donc
    elle pourrait faire passer pour une charge ce qui n'en est pas.

    Un JWT ordinaire — trois parties en base64url, dont une signature — ressort
    tel quel : sa charge ne rencontre rien à substituer, et c'est l'IDENTITÉ qui
    le rend, pas une exception écrite pour lui."""
    jwt = _jwt({"iss": "https://auth.example.com", "sub": "1234567890"})
    rendu = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"token": jwt}}).encode()))
    assert rendu["result"]["token"] == jwt


def test_a_jwt_payload_is_a_stated_residual(transform):
    """RÉSIDU ASSUMÉ, épinglé pour qu'il ne soit pas SILENCIEUX.

    Un JWT est du base64URL sans bourrage : ce n'est pas notre alphabet, et ses
    trois parties ne sont pas lues séparément. Une valeur réelle posée dans sa
    charge (`iss`) SORT DONC EN CLAIR pour qui décode la partie, et le sort du
    jeton dépend de l'alignement de ses longueurs — traversé quand la
    concaténation se décode, intact sinon. Ni l'un ni l'autre n'est un
    invariant défendable.

    Le test dit ce qui EST, pas ce qu'on voudrait : il rougira le jour où les
    parties seront lues une à une, et c'est exactement le signal attendu. La
    correction est au tour suivant ; ce qui compte ici est que le résidu soit
    compté."""
    import base64

    jwt = _jwt({"iss": "https://db-01.acme.internal/auth"})
    sortie = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"token": jwt}}).encode())
    )["result"]["token"]
    charge = sortie.split(".")[1]
    lue = base64.urlsafe_b64decode(charge + "=" * (-len(charge) % 4))
    assert b"db-01.acme.internal" in lue, \
        "les parties d'un JWT sont lues : mettre à jour docs/limits.md"


@pytest.mark.parametrize("prose", [
    "Hello, World!", "kubectl get pods -A", "2026-08-12T11:00:00Z",
    "aaaa bbbb cccc dddd", "abcd efgh ijkl mnop",
    "SELECT * FROM users WHERE id = 42;",
])
def test_ordinary_text_is_not_turned_into_a_payload(transform, prose):
    """La règle élargie ne doit pas transformer de la prose en base64. Certaines
    de ces chaînes prennent la FORME une fois la ponctuation retirée : ce qui
    les protège est le décodage, qui n'en tire pas de l'UTF-8, puis l'identité,
    qui rend la chaîne d'origine quand rien n'est substitué."""
    rendu = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"v": prose}}).encode()))
    assert rendu["result"]["v"] == prose


@pytest.mark.parametrize("visible", [".", ",", '"', " ", ";", ")"])
def test_no_visible_separator_can_switch_the_substitution_off(transform, visible):
    """La JUMELLE VISIBLE des caractères invisibles, et elle se mesure :
    `Buffer.from` de Node jette aussi le point, la virgule et le guillemet, et
    Python jette tout ce qui n'est pas de l'alphabet. Un contrat fondé sur les
    seuls caractères « bizarres » aurait donc laissé la porte ouverte à un
    caractère parfaitement ordinaire."""
    import base64

    reel = "db-01.acme.internal"
    canonique = base64.b64encode(reel.encode()).decode()
    piege = canonique[:14] + visible + canonique[14:]
    assert base64.b64decode(piege.encode("utf-8")).decode() == reel

    rendu = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"v": piege}}).encode()))["result"]["v"]
    assert reel not in base64.b64decode(rendu.encode("utf-8")).decode("utf-8", "replace")


@pytest.mark.parametrize("piege", ["= au milieu", "== au milieu", "= au début"])
def test_stray_padding_cannot_switch_the_substitution_off(transform, piege):
    """Python jette les `=` égarés et lit la valeur au travers, Node s'arrête au
    premier et en lit un PRÉFIXE. Deux lectures, donc, et n'en protéger qu'une
    laissait l'autre ouverte : la lecture par préfixe rendait `db-01.acm`, où
    rien n'est à substituer, et court-circuitait tout."""
    import base64

    reel = "db-01.acme.internal"
    c = base64.b64encode(reel.encode()).decode()
    valeur = {"= au milieu": c[:12] + "=" + c[12:],
              "== au milieu": c[:12] + "==" + c[12:],
              "= au début": "=" + c}[piege]
    rendu = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"v": valeur}}).encode()))["result"]["v"]
    for lu in (base64.b64decode(rendu.encode("utf-8")).decode("utf-8", "replace"),
               rendu):
        assert "db-01.acm" not in lu, lu


def test_a_plain_address_is_still_substituted_as_text(transform):
    """La lecture par préfixe a failli coûter cette protection : `10.1.2.3` se
    réduit à quatre caractères qui SE DÉCODENT, donc une lecture existait, ne
    portait rien, et rendait la chaîne telle quelle. Une lecture qui ne trouve
    rien ne doit jamais empêcher le texte d'être protégé."""
    rendu = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"v": "10.1.2.3"}}).encode()))
    assert rendu["result"]["v"] == "198.18.4.5"


@pytest.mark.parametrize("suffixe", ["XXXX", "ABCD", "SGVs", "XX"])
def test_no_alphabet_glued_after_padding_can_switch_the_substitution_off(
        transform, suffixe):
    """TÉMOIN MANQUANT du tour 15 — le correctif fermait trois formes, les
    tests n'en épinglaient que deux.

    Exiger que la chaîne ENTIÈRE ait la forme (`fullmatch`) était la troisième
    formulation d'un contrat plus étroit que celui du destinataire : quatre
    caractères d'alphabet collés derrière le bourrage suffisaient à l'éteindre,
    pendant que Python, Node et Go décodent tous le préfixe. Remplacer par
    `fullmatch` laisse aujourd'hui encore 216 tests verts — d'où celui-ci."""
    import base64

    reel = "db-01.acme.internal"
    piege = base64.b64encode(reel.encode()).decode() + suffixe
    assert base64.b64decode(piege.encode("utf-8")).decode() == reel

    rendu = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"v": piege}}).encode()))["result"]["v"]
    assert reel not in base64.b64decode(
        rendu.encode("utf-8")).decode("utf-8", "replace")


@pytest.mark.parametrize("reel", ["10.1.2.3", "db-01.acme.internal",
                                  "acme-billing"])
def test_base64_without_padding_is_still_substituted(transform, reel):
    """CRITIQUE, sixième occurrence — le bourrage RETIRÉ passait entre les deux
    lectures.

    `_BASE64` exige un `=` final, donc la lecture par préfixe s'arrête un
    quantum trop tôt et rend `db-01.acme.interna` : rien à substituer. Et la
    lecture large ne se déclenchait que sur un `=` égaré, qu'il n'y a pas ici.
    Python refuse un bourrage incomplet, mais `Buffer.from` de Node — qui EST
    l'implémentation MCP ordinaire — le complète et lit la valeur entière.

    Le déclencheur est désormais la NON-COUVERTURE, pas l'énumération des
    raisons qui la produisent : c'est cette énumération qui a été trop étroite
    trois fois de suite."""
    import base64

    sans = base64.b64encode(reel.encode()).decode().rstrip("=")
    rendu = json.loads(transform.outgoing("h", {}, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"v": sans}}).encode()))["result"]["v"]
    assert rendu != sans, "la charge n'a pas été vue"
    # Ce que Node en tire après nous : il complète le bourrage tout seul.
    lu = rendu.rstrip("=")
    assert reel not in base64.b64decode(
        (lu + "=" * (-len(lu) % 4)).encode("utf-8")).decode("utf-8", "replace")


@pytest.mark.parametrize("chemin", ["params", "result", "profond"])
def test_a_payload_in_a_KEY_is_traversed_too(transform, chemin):
    """CRITIQUE, septième occurrence — et le code contredisait son docstring.

    `_libre` annonce « la clé est une valeur comme une autre », et c'était vrai
    du TEXTE mais pas de ce qu'il ENCODE : les clés ne recevaient que le
    transformateur, jamais le lecteur de charges. Un serveur MCP qui range ses
    ressources sous `{"<base64>": {...}}` — la forme d'un dictionnaire indexé
    par identifiant — faisait donc sortir la valeur réelle verbatim, à toute
    profondeur et dans les deux sens.

    Aucun des seize tours précédents ne l'a vu parce que TOUS les tests de
    charge la mettent dans une VALEUR. Une position non testée est une position
    non protégée."""
    import base64

    reel = "db-01.acme.internal"
    charge = base64.b64encode(reel.encode()).decode()
    message = {
        "params": {"jsonrpc": "2.0", "id": 1, "method": "x",
                   "params": {charge: {"etat": "ok"}}},
        "result": {"jsonrpc": "2.0", "id": 1,
                   "result": {"resources": {charge: {"a": 1}}}},
        "profond": {"jsonrpc": "2.0", "id": 1,
                    "result": {"items": [{"l1": {"l2": {charge: 1}}}]}},
    }[chemin]
    sortie = transform.outgoing("h", {}, json.dumps(message).encode()).decode()
    assert charge not in sortie, sortie
    assert reel not in sortie


def test_a_key_that_is_an_opaque_payload_comes_back_identical(transform):
    """L'AUTRE MOITIÉ : une clé qui ressemble à du base64 sans rien porter doit
    traverser l'aller-retour inchangée, sinon le destinataire ne retrouve plus
    son index."""
    import base64

    opaque = base64.b64encode(b"nothing sensitive here").decode()
    message = {"jsonrpc": "2.0", "id": 1, "result": {"r": {opaque: 1}}}
    corps = json.dumps(message).encode()
    assert json.loads(transform.incoming("h", {}, transform.outgoing(
        "h", {}, corps))) == message
