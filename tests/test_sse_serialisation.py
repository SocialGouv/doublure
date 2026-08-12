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


@pytest.mark.parametrize("etype", [
    {"a": 1},                    # forme non scalaire
    "evil\ud800type",            # LA forme qui manquait : un demi-substitut
    "text_delta\udfff",
])
def test_le_type_reste_encodable_quoi_qu_il_porte(etype):
    """Un amont hostile met ce qu'il veut dans `type`, et l'en-tête doit rester
    encodable.

    Ce test ne couvrait QUE la forme dict, dont la représentation est de l'ASCII
    pur : elle survit trivialement. La forme qui compte — une chaîne portant un
    demi-substitut — levait sur la ligne d'en-tête, une ligne au-dessus du
    correctif qui venait de fermer la charge. Même fonction, même commit : le
    témoin mentait en n'exerçant que la moitié qui ne pouvait pas échouer."""
    rendu = encode_sse({"type": etype})
    assert rendu.startswith(b"event: ")
    assert rendu.endswith(b"\n\n")


def test_un_type_ordinaire_ressort_octet_pour_octet():
    """L'AUTRE MOITIÉ : le passage par l'encodeur sûr ne doit rien changer à un
    nom d'événement normal, accents compris."""
    assert encode_sse({"type": "message_stop"}).startswith(b"event: message_stop\n")
    assert encode_sse({"type": "événement"}).startswith(
        "event: événement\n".encode("utf-8"))



# `\u000b` et `\u001c` sont ECHAPPES par `json.dumps` : ils n'apparaissent
# jamais bruts dans un bloc, donc ils ne temoigneraient de rien. Seuls figurent
# ici les caracteres que `splitlines` coupe ET que le JSON laisse passer.
@pytest.mark.parametrize("separateur", ["\u2028", "\u2029", "\u0085"])
def test_un_bloc_reste_lisible_quels_que_soient_les_caracteres_du_TEXTE(
        separateur):
    """HAUT, restauration perdue en SILENCE.

    Le parsage decoupait avec `str.splitlines`, qui coupe sur U+2028, U+2029,
    U+0085 et les separateurs de fichier -- que le separateur de BLOCS, lui, ne
    reconnait pas. Or `json.dumps` ne les echappe pas hors mode ASCII : un tel
    caractere dans un texte faisait echouer le parsage, et **un bloc non parse
    part VERBATIM**, donc ses substituts ne sont jamais restaures et l'operateur
    lit un nom fictif sans rien pour le lui dire.

    Le decoupage suit desormais la spec SSE -- CRLF, CR, LF -- et rien d'autre.
    """
    from anonproxy.sse import parse_sse_block

    texte = f"avant{separateur}apres"
    bloc = "event: x\ndata: " + json.dumps({"type": "x", "t": texte},
                                           ensure_ascii=False)
    lu = parse_sse_block(bloc)
    assert lu is not None, repr(bloc)
    assert lu["t"] == texte


@pytest.mark.parametrize("fin", ["\r\n", "\r", "\n"])
def test_les_trois_fins_de_ligne_de_la_spec_sont_reconnues(fin):
    """L'AUTRE MOITIE : restreindre le decoupage ne doit pas perdre une fin de
    ligne que la spec autorise."""
    from anonproxy.sse import parse_sse_block

    assert parse_sse_block(f'event: x{fin}data: {{"type":"x"}}') == {"type": "x"}


@pytest.mark.parametrize("injecte", ["a\n\nb", "a\rb", "x\ndata: faux",
                                    "x\r\ndata: faux"])
def test_un_type_ne_peut_pas_alterer_la_STRUCTURE_du_bloc(injecte):
    """Le nom d'evenement ne doit pouvoir ni couper le bloc, ni y injecter une
    ligne.

    L'assertion porte sur l'ALLER-RETOUR, pas sur le compte de `\n\n` : celui-ci
    ne temoignait que d'une des deux attaques, et deux parametres sur trois
    passaient donc SANS le correctif tout en ayant l'air de le couvrir. Or
    `x\ndata: faux` injecte une ligne `data:` qui rend le bloc illisible — et un
    bloc qu'on ne parse pas part VERBATIM, substituts non restaures.

    Relire ce qu'on emet prend les trois formes d'un coup : la coupure de bloc,
    l'injection de ligne, et le `\r` nu."""
    from anonproxy.sse import iter_blocks, parse_sse_block

    rendu = encode_sse({"type": injecte})
    # La ligne du NOM ne porte aucune fin de ligne brute : un client conforme
    # decoupe sur `\r` seul autant que sur `\n`, et lirait alors un autre nom
    # que celui qu'on emet. Notre propre parseur, lui, tolere ce cas — d'ou
    # cette assertion, sans laquelle la forme `\r` nu ne temoignerait de rien.
    ligne_nom = rendu.split(b"\ndata: ", 1)[0]
    assert b"\r" not in ligne_nom and b"\n" not in ligne_nom[7:], rendu

    blocs, reste = iter_blocks(rendu.decode("utf-8"), "")
    assert len(blocs) == 1, blocs
    assert reste == ""
    assert parse_sse_block(blocs[0]) == {"type": injecte}


def test_un_bloc_illisible_est_COMPTE_pas_confondu_avec_un_ping():
    """`None` disait DEUX choses : « rien a faire » et « des donnees que je ne
    sais pas lire ».

    Le second part VERBATIM, donc ses substituts ne sont jamais restaures et
    l'operateur lit un nom fictif — sous un commentaire du code qui annoncait
    un ping. Relayer reste le bon choix (couper le flux serait pire), mais un
    residu se COMPTE, il ne se tait pas."""
    from anonproxy.sse import BlocSSEIllisible, parse_sse_block

    # Rien a faire : ce sont bien des None.
    assert parse_sse_block(": keep-alive") is None
    assert parse_sse_block("data: [DONE]") is None
    assert parse_sse_block("event: x") is None

    # Des donnees illisibles : c'est autre chose, et ca se dit.
    with pytest.raises(BlocSSEIllisible):
        parse_sse_block('event: x\ndata: {"type": "x"')


@pytest.mark.parametrize("charge", ["true", "false", "42", '"une chaine"',
                                    "[1,2,3]", "null"])
def test_une_charge_JSON_qui_n_est_pas_un_objet_ne_tue_pas_le_flux(charge):
    """HAUT, flux interrompu — le contrat annonce `dict | None` et ne le tenait
    pas.

    `true`, `42`, une liste, une chaine sont du JSON parfaitement valide. Le
    reecriveur levait alors `AttributeError` sur `event.get`, l'exception etait
    rattrapee au niveau de la BOUCLE, et le flux s'arretait la : tous les
    evenements suivants perdus, `message_stop` compris, donc un client qui
    attend sans fin.

    Un contrat qu'on annonce se tient : ces charges levent `BlocSSEIllisible`,
    que l'appelant compte et relaie sans casser le flux."""
    from anonproxy.sse import BlocSSEIllisible, parse_sse_block

    with pytest.raises(BlocSSEIllisible):
        parse_sse_block(f"event: x\ndata: {charge}")


def test_un_objet_reste_un_objet():
    """L'AUTRE MOITIE : la forme legitime passe."""
    from anonproxy.sse import parse_sse_block

    assert parse_sse_block('event: x\ndata: {"type":"x"}') == {"type": "x"}
