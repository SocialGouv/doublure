"""Défauts d'`anthropic_walker.py` mis en évidence par du trafic RÉEL.

Règle de travail : le walker est fourni tel quel et n'est corrigé que si un
test le met en défaut. Ces deux tests sont ces preuves.

DÉFAUT 1 — plantage sur une propriété nommée « type »
    `_walk` teste `node.get("type") in OPAQUE_BLOCK_TYPES` sur TOUT dict.
    Dans un JSON Schema, `properties` peut contenir une propriété nommée
    « type » dont la valeur est un objet : `node.get("type")` renvoie alors un
    dict, et l'appartenance à un frozenset lève `TypeError: unhashable type`.
    Observé en session réelle (outil dont un paramètre s'appelle « type ») :
    le proxy renvoie 500 et Claude Code s'arrête.

DÉFAUT 2 — descriptions de propriétés non substituées (fuite)
    La branche dédiée aux `properties` est morte : « properties » figure dans
    SCHEMA_STRUCTURAL_KEYS, dont la branche est testée AVANT. Les définitions
    de propriétés passent donc par la traversée générique, où SKIP_KEYS
    s'applique aux NOMS de propriétés : une propriété nommée « name », « id »
    ou « data » voit sa `description` recopiée telle quelle. Or les
    descriptions d'outils MCP contiennent souvent des noms d'hôtes internes —
    c'est la fuite que le plan §7 appelle « la plus discrète ».
"""
from __future__ import annotations

import json


from anthropic_walker import Substituter, walk_request


def marker_sub() -> Substituter:
    return Substituter(to_surrogate=lambda s: s.replace("SECRET-HOST", "fake-host"))


def test_defaut1_propriete_nommee_type_ne_plante_pas():
    """Reproduit le 500 observé en session réelle."""
    body = {
        "tools": [{
            "name": "create_resource",
            "description": "crée une ressource",
            "input_schema": {
                "type": "object",
                "properties": {
                    # une propriété qui s'appelle « type » : légal et courant
                    "type": {"type": "string", "enum": ["pod", "service"],
                             "description": "type de ressource sur SECRET-HOST"},
                    "name": {"type": "string"},
                },
                "required": ["type"],
            },
        }],
    }
    out = walk_request(body, marker_sub())  # ne doit pas lever
    assert out["tools"][0]["input_schema"]["required"] == ["type"]
    assert "type" in out["tools"][0]["input_schema"]["properties"]


def test_defaut2_description_de_propriete_reservee_substituee():
    """Une propriété nommée comme une clé de SKIP_KEYS doit quand même être traitée."""
    body = {
        "tools": [{
            "name": "query",
            "description": "interroge",
            "input_schema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "nom d'hôte, ex. SECRET-HOST"},
                    "id": {"type": "string", "description": "identifiant sur SECRET-HOST"},
                    "data": {"type": "string", "description": "charge utile SECRET-HOST"},
                    "host": {"type": "string", "description": "hôte SECRET-HOST"},
                },
            },
        }],
    }
    out = walk_request(body, marker_sub())
    blob = json.dumps(out)
    assert "SECRET-HOST" not in blob, (
        "fuite : la description d'une propriété nommée name/id/data n'a pas été substituée"
    )
    # les NOMS de propriétés restent le contrat avec le modèle
    props = out["tools"][0]["input_schema"]["properties"]
    assert set(props) == {"name", "id", "data", "host"}
    assert props["host"]["type"] == "string"


def test_defaut3_cles_structurelles_de_schema_preservees():
    """DÉFAUT 3 — la mécanique du schéma ne doit JAMAIS être substituée.

    Observé en session réelle : `$schema` vaut
    `https://json-schema.org/draft/2020-12/schema`, le détecteur y voit une
    URL, le walker la substitue → l'API répond 400 « JSON schema is invalid »
    et Claude Code s'arrête net.

    `required` est pire encore : c'est la liste des NOMS de propriétés. Les
    noms de propriétés, eux, ne sont pas substitués (contrat avec le modèle) ;
    substituer `required` casse donc la correspondance en silence.

    Le walker documente pourtant l'intention correcte : « On traverse
    `description`, on ignore la mécanique du schéma. » — l'implémentation
    traversait aussi la mécanique.
    """
    def sub_everything(s: str) -> str:
        # détecteur agressif : tout ce qui ressemble à une URL ou à un mot
        if s.startswith("http"):
            return "https://harbour.example.org/draft/2020-12/schema"
        return {"host": "MODIFIÉ", "port": "MODIFIÉ"}.get(s, s)

    body = {
        "tools": [{
            "name": "query",
            "description": "interroge un hôte",
            "input_schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "hôte SECRET-HOST"},
                    "port": {"type": "integer"},
                },
                "required": ["host", "port"],
                "additionalProperties": False,
            },
        }],
    }
    out = walk_request(body, Substituter(to_surrogate=sub_everything))
    schema = out["tools"][0]["input_schema"]

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema", \
        "$schema substitué → l'API rejette la requête (400)"
    assert schema["required"] == ["host", "port"], \
        "`required` substitué → ne correspond plus aux noms de propriétés"
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"host", "port"}


def test_defaut4_surfaces_sortantes_non_enumerables():
    """DÉFAUT 4 — `walk_request` était FAIL-OPEN sur les surfaces.

    Il n'itérait que sur ("system", "messages", "tools", "metadata"). Or
    /v1/messages accepte aussi `stop_sequences`, `mcp_servers`, `container`,
    `tool_choice` — tous porteurs de texte libre — et Anthropic ajoute des
    champs sans préavis : la capture réelle de la Phase 3 montre déjà
    `context_management`, `output_config` et `thinking` au premier niveau.

    Une liste blanche de surfaces laisse fuir tout champ futur. On inverse :
    on traverse TOUT sauf les clés de contrôle connues.
    """
    body = {
        "model": "claude-fable-5",
        "max_tokens": 4096,
        "temperature": 0.7,
        "stream": True,
        "service_tier": "auto",
        "betas": ["context-management-2025-06-27"],
        "thinking": {"type": "adaptive", "display": "omitted"},
        "output_config": {"effort": "max"},
        "context_management": {"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]},
        "messages": [{"role": "user", "content": "bonjour"}],
        # ↓ surfaces porteuses de texte, hors des quatre historiques
        "stop_sequences": ["FIN-SECRET-HOST"],
        "tool_choice": {"type": "tool", "name": "query_db"},
        "mcp_servers": [{
            "type": "url", "name": "infra",
            "url": "https://mcp.SECRET-HOST/tools",
            "tool_configuration": {"allowed_tools": ["query_on_SECRET-HOST"]},
        }],
        "container": {"image": "registry.SECRET-HOST/tools:1.0"},
    }
    out = walk_request(body, marker_sub())
    blob = json.dumps(out)

    assert "SECRET-HOST" not in blob, "fuite : une surface non énumérée n'est pas traitée"

    # les clés de contrôle restent intactes (les substituer casserait l'API)
    assert out["model"] == "claude-fable-5"
    assert out["max_tokens"] == 4096 and out["temperature"] == 0.7
    assert out["service_tier"] == "auto"
    assert out["betas"] == ["context-management-2025-06-27"]
    assert out["thinking"] == {"type": "adaptive", "display": "omitted"}
    assert out["output_config"] == {"effort": "max"}
    assert out["context_management"] == body["context_management"]
    # le nom d'outil reste un contrat
    assert out["tool_choice"]["name"] == "query_db"


def test_defaut5_reponse_restauree_hors_content():
    """DÉFAUT 5 — `walk_response` ne restaurait QUE `body["content"]`.

    Tout substitut apparaissant ailleurs (message d'erreur amont,
    `stop_sequence` renvoyée en écho, champ ajouté par une version future)
    restait sous sa forme fictive côté opérateur : celui-ci lit un nom d'hôte
    qui n'existe pas, et le modèle peut ensuite le reprendre dans un tour
    suivant. Ce n'est pas une fuite, c'est une incohérence silencieuse.
    """
    from anthropic_walker import walk_response

    sub = Substituter(to_surrogate=lambda s: s,
                      surrogates={"cluster-01.northwind.internal": "db-01.acme.internal"})
    body = {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "model": "claude-fable-5",
        "content": [{"type": "text", "text": "vu cluster-01.northwind.internal"}],
        "stop_reason": "stop_sequence",
        "stop_sequence": "FIN-cluster-01.northwind.internal",
        "error": {"type": "api_error", "message": "échec sur cluster-01.northwind.internal"},
        "usage": {"input_tokens": 10, "output_tokens": 3},
    }
    out, unresolved = walk_response(body, sub)

    assert out["content"][0]["text"] == "vu db-01.acme.internal"
    assert out["stop_sequence"] == "FIN-db-01.acme.internal", "écho de stop_sequence non restauré"
    assert out["error"]["message"] == "échec sur db-01.acme.internal"
    # les identifiants de protocole restent intacts
    assert out["id"] == "msg_01" and out["model"] == "claude-fable-5"
    assert out["stop_reason"] == "stop_sequence"
    assert out["usage"] == {"input_tokens": 10, "output_tokens": 3}
    assert unresolved == []


def test_defaut5bis_message_delta_streame_restaure():
    """Même surface en streaming : `message_delta` porte l'écho de
    `stop_sequence`, `error` porte un message. Tous deux passaient bruts."""
    from anthropic_walker import SSERewriter

    sub = Substituter(to_surrogate=lambda s: s,
                      surrogates={"cluster-01.northwind.internal": "db-01.acme.internal"})
    rw = SSERewriter(sub)
    events = [
        {"type": "message_delta",
         "delta": {"stop_reason": "stop_sequence",
                   "stop_sequence": "FIN-cluster-01.northwind.internal"},
         "usage": {"output_tokens": 7}},
        {"type": "error",
         "error": {"type": "api_error", "message": "échec sur cluster-01.northwind.internal"}},
    ]
    out = [e for ev in events for e in rw.feed(ev)]
    assert out[0]["delta"]["stop_sequence"] == "FIN-db-01.acme.internal"
    assert out[0]["delta"]["stop_reason"] == "stop_sequence"
    assert out[0]["usage"] == {"output_tokens": 7}
    assert out[1]["error"]["message"] == "échec sur db-01.acme.internal"


def test_defaut6_sous_arbre_de_controle_inattendu_traverse():
    """DÉFAUT 6 — une clé de contrôle excluait tout son SOUS-ARBRE.

    Le fail-closed de `walk_request` ne valait qu'au premier niveau : le jour
    où Anthropic ajoute un champ porteur de texte DANS `thinking`,
    `output_config` ou `context_management`, il sortait brut. Or ces blocs
    évoluent avec les betas.

    Règle retenue : on ne saute un bloc de contrôle que si sa FORME est celle
    qu'on connaît. Toute clé inattendue le fait traverser.
    """
    connu = {
        "thinking": {"type": "adaptive", "display": "omitted"},
        "output_config": {"effort": "max"},
        "context_management": {"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]},
        "betas": ["context-management-2025-06-27"],
        "messages": [{"role": "user", "content": "bonjour"}],
    }
    out = walk_request(connu, marker_sub())
    assert out["thinking"] == connu["thinking"], "forme connue : ne pas toucher"
    assert out["output_config"] == connu["output_config"]
    assert out["context_management"] == connu["context_management"]
    assert out["betas"] == connu["betas"]

    for cle, valeur in (
        ("thinking", {"type": "adaptive", "custom_prompt": "cible SECRET-HOST"}),
        ("output_config", {"effort": "max", "prompt_hint": "sur SECRET-HOST"}),
        ("context_management", {"edits": [{"type": "clear", "description": "SECRET-HOST"}]}),
    ):
        out = walk_request({cle: valeur, "messages": []}, marker_sub())
        assert "SECRET-HOST" not in json.dumps(out[cle]), \
            f"fuite : champ inattendu dans `{cle}` non traversé"


def test_defaut7_document_en_texte_brut_traverse():
    """DÉFAUT 7 — `data` était sauté quelle que soit la nature de la source.

    `data` figure dans SKIP_KEYS pour protéger les charges base64 d'images et
    de PDF. Mais l'API accepte aussi `document.source = {"type": "text",
    "media_type": "text/plain", "data": "<texte libre>"}` : c'est le chemin
    naturel pour joindre un log ou un extrait de configuration. Tout ce texte
    partait en clair.
    """
    body = {"messages": [{"role": "user", "content": [
        {"type": "document",
         "source": {"type": "text", "media_type": "text/plain",
                    "data": "journal du jour : SECRET-HOST est tombé"}},
        # la source binaire, elle, doit rester intouchée
        {"type": "document",
         "source": {"type": "base64", "media_type": "application/pdf",
                    "data": "JVBERi0xLjQKJSSECRET-HOSTZmFrZQ=="}},
        {"type": "image",
         "source": {"type": "base64", "media_type": "image/png", "data": "iVBORSECRET-HOST"}},
    ]}]}
    out = walk_request(body, marker_sub())
    blocs = out["messages"][0]["content"]

    assert "SECRET-HOST" not in blocs[0]["source"]["data"], \
        "fuite : le texte brut d'un document n'est pas traversé"
    assert blocs[0]["source"]["media_type"] == "text/plain"
    # base64 : contenu opaque, on n'y touche pas (le substituer corromprait
    # le document et n'apporterait rien).
    assert blocs[1]["source"]["data"] == "JVBERi0xLjQKJSSECRET-HOSTZmFrZQ=="
    assert blocs[2]["source"]["data"] == "iVBORSECRET-HOST"


def test_types_de_blocs_opaques_toujours_respectes():
    """Garde-fou : la correction ne doit pas affaiblir D3."""
    body = {
        "messages": [{
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "SECRET-HOST", "signature": "s"},
                {"type": "redacted_thinking", "data": "SECRET-HOST"},
                {"type": "text", "text": "SECRET-HOST"},
            ],
        }],
    }
    out = walk_request(body, marker_sub())
    blocks = out["messages"][0]["content"]
    assert blocks[0]["thinking"] == "SECRET-HOST", "bloc thinking modifié (D3)"
    assert blocks[1]["data"] == "SECRET-HOST", "bloc redacted_thinking modifié (D3)"
    assert blocks[2]["text"] == "fake-host", "le texte normal doit être substitué"
