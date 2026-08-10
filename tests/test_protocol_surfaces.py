"""An enum is the tool's CLOSED vocabulary, not data.

Written BEFORE the fix, for two reasons. `anthropic_walker.py` is supplied as
is and is only corrected once a test proves it wrong (working rule 2). And this
rule WIDENS what leaves verbatim — the one family whose failure mode is a
SILENT leak (round 8): no 400, no 503, no vault entry, nothing to count. So
both directions are pinned here, in the same file: what must stay, and what
must still be substituted.

Measured in a real session: 248 arbitration questions for about fifteen
legitimate ones. `sonnet`, `auto`, `AVAILABILITY_BUSY`, `THREAD_VIEW_MINIMAL`,
`low`, `medium` are enum members of tool schemas, substituted as though they
were infrastructure identifiers.

Substituting them leaks nothing — the call is restored on the way back. It
destroys the MEANING. The model is told the permitted values are
`glacier-vault10` and `tundra-planner03`; it cannot know which one stands for
`low`, so it picks one and the tool runs on the wrong value. Nothing reports an
error. That is the same silent class as a broken `type` at round 3, reached
from the other side: there the API refused, here it accepts and obeys.

The guard is by FORM, exactly as SCALAR_SKIP_FORMS: a member with no dot, no
slash, no at-sign, no colon and no space cannot be an FQDN, a path, a URL, an
address or an IP. A well-formed media type passes too — same closed IANA
registry as `media_type`.
"""
from __future__ import annotations

import json

import pytest

from anthropic_walker import Substituter, walk_request


def sabotage() -> Substituter:
    """Substitutes EVERYTHING it is given: what survives was never offered."""
    return Substituter(to_surrogate=lambda s: "SABOTAGE")


def sabotage_injectif() -> Substituter:
    """Même chose, mais INJECTIF — indispensable dès qu'un dict a plusieurs
    clés : les clés de données sont substituées, et un substituteur qui écrase
    tout vers la même chaîne déclenche la garde de collision, qui est là pour
    empêcher une perte de valeur silencieuse. Renverser est injectif et ne
    laisse aucune sous-chaîne de l'original."""
    return Substituter(to_surrogate=lambda s: s[::-1])


def schema_with(members: list, **extra) -> dict:
    return {"tools": [{
        "name": "run_task",
        "description": "runs a task",
        "input_schema": {
            "type": "object",
            "properties": {
                "effort": {"type": "string", "enum": members, **extra},
            },
        },
    }]}


def effort_of(out: dict) -> dict:
    return out["tools"][0]["input_schema"]["properties"]["effort"]


# --------------------------------------------------------------------------- #
# What must stay — the vocabulary the model reasons with
# --------------------------------------------------------------------------- #

VOCABULARY = ["sonnet", "auto", "AVAILABILITY_BUSY", "THREAD_VIEW_MINIMAL",
              "low", "medium", "high", "claude-opus-4-5-20251101", "pod"]


def test_enum_members_keep_their_meaning():
    out = walk_request(schema_with(VOCABULARY), sabotage())
    assert effort_of(out)["enum"] == VOCABULARY


MEDIA_TYPES = ["application/json", "text/plain", "image/png", "text/csv"]


@pytest.mark.parametrize("value", MEDIA_TYPES)
def test_a_media_type_in_an_enum_stays_verbatim(value):
    """A media type carries a slash and dots, so the token form rejects it.
    It is nonetheless a closed registry, already pinned for `media_type`."""
    out = walk_request(schema_with([value]), sabotage())
    assert effort_of(out)["enum"] == [value]


def test_non_string_members_are_untouched():
    out = walk_request(schema_with([1, 2.5, True, None]), sabotage())
    assert effort_of(out)["enum"] == [1, 2.5, True, None]


def test_a_default_echoing_an_enum_member_follows_it():
    """A default substituted while its enum is not is no longer a legal value:
    the model reads a schema whose own default is outside its constraint."""
    out = walk_request(schema_with(["auto", "manual"], default="auto"),
                       sabotage())
    assert effort_of(out)["default"] == "auto"


# --------------------------------------------------------------------------- #
# What must still be substituted — the guard has to bite
# --------------------------------------------------------------------------- #

IDENTIFIERS = [
    "db-01.acme.internal",
    "acme.internal",
    "/home/jo/.config/acme",
    "alice@acme.corp",
    "https://vault.acme.internal/v1",
    "10.4.2.17",
    "fd00:1234::beef",
    "srv.acme.corp:8443",
    "C:\\Users\\jo\\acme",
    "db 01 acme internal",
]


@pytest.mark.parametrize("value", IDENTIFIERS)
def test_an_enum_member_that_identifies_is_still_substituted(value):
    out = walk_request(schema_with(["auto", value]), sabotage())
    assert value not in json.dumps(effort_of(out)["enum"], ensure_ascii=False)


def test_an_example_outside_the_enum_stays_data():
    """Round 7 settled it: `default`, `example` and `const` carry EXAMPLE
    values, where a hostname is data. Only the echo of a member the enum
    already publishes verbatim may follow the enum."""
    body = schema_with(["auto"],
                       default="db-01.acme.internal",
                       example="db-01.acme.internal",
                       const="db-01.acme.internal")
    assert "db-01.acme.internal" not in json.dumps(walk_request(body, sabotage()))


def test_an_enum_inside_tool_arguments_is_data():
    """`input` holds parameter names chosen by a third party. A forged
    `input_schema` placed there must not buy protocol protection — the exact
    forgery closed at rounds 4, 10, 11 and 12, reached through a new key."""
    body = {"messages": [{"role": "assistant", "content": [{
        "type": "tool_use", "id": "toolu_1", "name": "register",
        "input": {"input_schema": {"properties": {
            "target": {"type": "string", "enum": ["db-01.acme.internal"]},
        }}},
    }]}]}
    assert "db-01.acme.internal" not in json.dumps(
        walk_request(body, sabotage_injectif()))


SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "sk-ant-api03-Zx9QwErTyUiOpAsDfGhJkL",
    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
]


@pytest.mark.parametrize("value", SECRETS)
def test_a_secret_never_rides_out_inside_an_enum(value):
    """The guard bypasses the detector, so anything the detector would have
    caught becomes invisible — including the SECRET class, which D4 says is a
    reference and never leaves. A vocabulary token is not a high-entropy blob:
    a long segment MIXING letters and digits is the signature of a drawn
    identifier, never of a word."""
    out = walk_request(schema_with(["auto", value]), sabotage())
    assert value not in json.dumps(effort_of(out)["enum"], ensure_ascii=False)


@pytest.mark.parametrize("value", [
    "application/vnd.db-01.acme.internal",
    "application/vnd.10.0.5.7",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.api+json",
])
def test_the_vendor_tree_of_a_media_type_is_not_closed(value):
    """The top-level registry is closed; the `vnd.`/`prs.` tree is NOT — RFC
    6838 §3.2 lets anyone register the labels they like, and it accepts dots.
    A multi-label host and an IPv4 both fit in it. Real Office and vendor JSON
    types pay for it by being substituted inside an enum: damaging one is
    visible, letting an internal host out is not."""
    out = walk_request(schema_with([value]), sabotage())
    assert value not in json.dumps(effort_of(out)["enum"], ensure_ascii=False)


@pytest.mark.parametrize("position", ["mcp_servers", "tool_choice"])
def test_a_schema_must_be_a_direct_child_of_a_tool(position):
    """`protocole` se propage à TOUT descendant d'un conteneur de protocole :
    exiger ce drapeau laissait donc `input_schema` légitime à n'importe quelle
    profondeur sous `tools`, `mcp_servers` ou `tool_choice`. La position d'un
    schéma est celle d'un ENFANT DIRECT d'un outil, pas celle d'un descendant
    quelconque. C'est la troisième fois que cette classe se referme mal :
    restreinte au round 11, re-restreinte au tour 1, encore trop large."""
    enum = {"properties": {"a": {"enum": ["SECRET-tenant-alpha"]}}}
    bodies = {
        "mcp_servers": {"mcp_servers": [{
            "type": "url", "name": "s", "url": "https://x/",
            "tool_configuration": {"input_schema": enum}}]},
        "tool_choice": {"tool_choice": {"type": "tool", "name": "f",
                                        "input_schema": enum}},
    }
    out = json.dumps(walk_request(bodies[position], sabotage()))
    assert "SECRET-tenant-alpha" not in out


@pytest.mark.parametrize("value", [
    "application/x-AKIAIOSFODNN7EXAMPLE",
    "text/x-AKIAJXQNJDLZBSCGKPQR",
    "application/x-eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
])
def test_a_media_type_is_not_a_channel_for_secrets(value):
    """La branche « type de média » rendait la valeur AVANT d'appeler la garde
    d'opacité : le sous-type est du texte libre, et `application/x-<secret>`
    sortait donc verbatim. La garde vaut pour les deux chemins."""
    out = walk_request(schema_with([value]), sabotage())
    assert value not in json.dumps(effort_of(out)["enum"], ensure_ascii=False)


@pytest.mark.parametrize("value", [
    "AKIAJXQNJDLZBSCGKPQR",                        # clé AWS SANS aucun chiffre
    "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",    # jeton OAuth tout en lettres
    "xoxb-REDACTED-TEST-FIXTURE",
    "alice-dupont-directrice-financiere",          # PII en segments courts
    "aa-bb-cc-dd-ee-ff",                           # adresse MAC en tirets
])
def test_a_drawn_identifier_is_opaque_even_without_a_digit(value):
    """La règle « segment long ET mixte » ne voyait qu'une classe de secrets :
    ceux qui sont DENSES. Tout ce qui porte des séparateurs lui échappait, et
    une clé AWS n'a un chiffre qu'avec 98,6 % de probabilité — sur soixante-dix
    clés, une passe. Trois bornes s'y ajoutent : un segment de seize
    caractères, un total de plus de trente-deux, et la forme d'une MAC."""
    out = walk_request(schema_with([value]), sabotage())
    assert value not in json.dumps(effort_of(out)["enum"], ensure_ascii=False)


def test_a_parameter_NAME_is_data_too():
    """Les CLÉS d'un dictionnaire n'étaient substituées nulle part. Dans des
    arguments d'outil, une clé est un nom choisi par l'appelant : le modèle
    écrit `{"db-01.acme.internal": …}` et le nom d'hôte sortait verbatim, sans
    entrée de coffre — et sans restauration au retour, donc l'outil se serait
    exécuté sur le nom FICTIF. Ce que le détecteur ne signale pas (`path`,
    `command`) reste évidemment intact."""
    body = {"messages": [{"role": "user", "content": [{
        "type": "tool_use", "id": "t1", "name": "f",
        "input": {"db-01.acme.internal": "x"}}]}]}
    assert "db-01.acme.internal" not in json.dumps(walk_request(body, sabotage()))


@pytest.mark.parametrize("body", [
    # sortie d'un serveur MCP, relayée dans un `tool_result`
    {"messages": [{"role": "user", "content": [{
        "type": "tool_result", "tool_use_id": "t1", "content": [
            {"type": "resource", "resource": {"srv-01.acme.internal": "x"}}]}]}]},
    # sous-arbre de forme INCONNUE : sa structure n'est pas celle de l'API
    {"messages": [{"role": "user", "content": [{
        "type": "text", "text": "x",
        "cache_control": {"type": "ephemeral",
                          "inconnu": {"srv-01.acme.internal": "y"}}}]}]},
])
def test_a_key_written_by_a_third_party_is_data(body):
    """N'ouvrir les clés que sous `input` a RÉTRÉCI la classe, pas fermée : la
    sortie d'un serveur MCP arrive dans le `content` d'un `tool_result`, et un
    sous-arbre de forme inconnue est par définition hors protocole. Forger le
    type d'un bloc pour obtenir ce traitement ne fait qu'AUGMENTER la
    substitution — c'est le seul sens où une forgerie est sans danger."""
    assert "srv-01.acme.internal" not in json.dumps(walk_request(body, sabotage()))


def test_two_keys_never_collapse_into_one():
    """`out[cle] = …` écrasait en silence : deux clés réelles distinctes
    tirant le même substitut, une valeur DISPARAISSAIT du corps sans que rien
    ne le signale. Un résidu accepté se compte ; une perte de donnée se
    refuse."""
    from anthropic_walker import Substituter as S
    collision = S(to_surrogate=lambda s: "MEME" if s.startswith("srv") else s)
    body = {"messages": [{"role": "assistant", "content": [{
        "type": "tool_use", "id": "t", "name": "f",
        "input": {"srv-a.acme.internal": "V1", "srv-b.acme.internal": "V2"}}]}]}
    with pytest.raises(ValueError, match="collision"):
        walk_request(body, collision)


@pytest.mark.parametrize("value", [
    "text/plain; srv-billing-prod-01=x",
    "text/plain; my-corporate-billing-tenant=v",
])
def test_the_NAME_of_a_media_parameter_is_bounded_too(value):
    """La borne portait sur la VALEUR du paramètre. Son NOM est tout aussi
    libre, et un identifiant y tenait entier."""
    out = walk_request(schema_with([value]), sabotage())
    assert value not in json.dumps(effort_of(out)["enum"], ensure_ascii=False)


@pytest.mark.parametrize("bloc", [
    {"effort": "high"},
    {"effort": "high", "verbosity": "low"},          # une cle ajoutee par l'amont
    {"effort": "high", "futur": "medium", "n": 3},
])
def test_an_inference_parameter_survives_a_new_field(bloc):
    """Mesuré en session RÉELLE : le client s'est mis à envoyer une clé de plus
    dans `output_config`, la clé inconnue a fait traverser le bloc ENTIER,
    `effort` est parti au détecteur et en est revenu substitué — l'API a
    répondu 400 et la session s'est arrêtée. Énumérer les sous-clés d'un bloc
    que l'amont fait évoluer est un pari perdu ; la FORME, elle, tient."""
    assert walk_request({"output_config": bloc}, sabotage()) == {
        "output_config": bloc}


def test_an_inference_parameter_is_not_a_data_channel():
    """Le pendant : la clé est libre, la forme ne l'est pas."""
    out = walk_request({"output_config": {"effort": "db-01.acme.internal"}},
                       sabotage())
    assert out["output_config"]["effort"] != "db-01.acme.internal"


def test_a_protocol_key_is_not_renamed():
    """Le pendant : hors données utilisateur, une clé est du PROTOCOLE. La
    renommer casserait la requête bien avant toute question de fuite."""
    body = {"tools": [{"name": "f", "description": "d",
                       "input_schema": {"type": "object"}}]}
    out = walk_request(body, sabotage())
    assert set(out["tools"][0]) == {"name", "description", "input_schema"}


TOOL = [{"name": "f", "description": "d", "input_schema": {
    "properties": {"r": {"enum": ["alice-durand"]}}}}]


@pytest.mark.parametrize("body", [
    {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "x", "tools": TOOL}]}]},
    {"system": [{"type": "text", "text": "x", "tools": TOOL}]},
    {"mcp_servers": [{"type": "url", "name": "s", "url": "https://x/",
                      "tools": TOOL}]},
])
def test_a_nested_tools_key_buys_nothing(body):
    """Le drapeau était RE-DÉRIVÉ de la clé à chaque niveau
    (`dans_outils=(key == "tools")`), donc n'importe quelle clé `tools`
    imbriquée rouvrait le traitement schéma. La position ne se DÉDUIT pas
    d'un nom de clé — c'est la cinquième fois que cette classe se referme mal.
    Elle est SEMÉE à la racine, propagée d'un cran par la liste, et remise à
    faux partout ailleurs."""
    assert "alice-durand" not in json.dumps(walk_request(body, sabotage()))


@pytest.mark.parametrize("payload", [
    {"type": "srv-01.acme.internal"},
    {"required": ["db-master.acme.internal"]},
    {"format": "https://srv-01.acme.internal/x"},
    {"$anchor": "/var/lib/secrets/api-key"},
    {"properties": {"srv-billing.acme.internal": {"type": "string"}}},
    {"dependencies": {"a": ["10.20.30.40"]}},
])
def test_an_enum_member_is_a_value_not_a_schema(payload):
    """Un membre d'enum qui n'est pas du vocabulaire était traversé avec
    `in_schema=True` : les clés structurelles d'un schéma y devenaient
    verbatim, et `{"type": "srv-01.acme.internal"}` sortait entier. Un membre
    d'enum est une VALEUR que le modèle doit émettre — jamais un fragment de
    schéma, même quand il en a la forme."""
    body = schema_with([payload])
    for secret in ("srv-01.acme.internal", "db-master.acme.internal",
                   "/var/lib/secrets/api-key", "srv-billing.acme.internal",
                   "10.20.30.40"):
        assert secret not in json.dumps(walk_request(body, sabotage()))


@pytest.mark.parametrize("value", [
    "application/json; charset=ghp_abcdef1234",
    "text/plain; boundary=AKIAIOSFODNN7EXAMPLE",
])
def test_a_media_type_parameter_is_not_a_free_channel(value):
    """La garde d'opacité ne portait que sur le SOUS-TYPE. Les paramètres —
    `charset`, `boundary` — sont du texte libre, et une clé AWS y tenait
    entière alors qu'elle est attrapée quand on la présente seule."""
    out = walk_request(schema_with([value]), sabotage())
    assert value not in json.dumps(effort_of(out)["enum"], ensure_ascii=False)


def test_a_legitimate_media_type_with_a_parameter_survives():
    """Le pendant : `; charset=utf-8` est du protocole, pas une charge."""
    v = "application/json; charset=utf-8"
    assert effort_of(walk_request(schema_with([v]), sabotage()))["enum"] == [v]


@pytest.mark.parametrize("position", ["tool_result", "system", "document"])
def test_a_schema_forged_outside_the_tools_container_is_data(position):
    """Legitimacy is a property of POSITION: it descends from `tools`, it is not
    bought by writing the key `input_schema` in one's own subtree. A hostile MCP
    server nests it in its output and the guard would apply two levels below a
    `tool_result`. Same remedy as round 11, reached through a new key."""
    enum = {"properties": {"h": {"enum": ["db-prod01", "srv-billing-02"]}}}
    bodies = {
        "tool_result": {"messages": [{"role": "user", "content": [{
            "type": "tool_result", "tool_use_id": "t1",
            "content": [{"type": "resource",
                         "resource": {"input_schema": enum}}]}]}]},
        "system": {"system": [{"type": "text", "text": "x",
                               "input_schema": enum}]},
        "document": {"messages": [{"role": "user", "content": [{
            "type": "document", "source": {"input_schema": enum}}]}]},
    }
    out = json.dumps(walk_request(bodies[position], sabotage()))
    assert "db-prod01" not in out and "srv-billing-02" not in out


def test_an_enum_outside_a_schema_is_data():
    """`enum` is a schema keyword. Under a `tool_result` returned by an MCP
    server it is an ordinary key, and its members are that server's output."""
    body = {"messages": [{"role": "user", "content": [{
        "type": "tool_result", "tool_use_id": "toolu_1",
        "content": [{"type": "text", "text": "x"}],
        "enum": ["db-01.acme.internal"],
    }]}]}
    assert "db-01.acme.internal" not in json.dumps(walk_request(body, sabotage()))
