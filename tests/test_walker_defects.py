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

import pytest

from anthropic_walker import Substituter, walk_request, walk_response


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
            # `allowed_tools` est un FILTRE évalué contre les noms réels du
            # serveur MCP : le substituer casserait l'exposition de l'outil.
            # Même fuite assumée que `tools[].name` — la valeur y est un nom de
            # routage, pas une donnée (assertion dédiée plus bas).
            "tool_configuration": {"allowed_tools": ["query_db"]},
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
    # `allowed_tools` aussi : c'est un filtre évalué contre les noms exposés
    # par le serveur MCP, le substituer le casserait EN SILENCE.
    assert out["mcp_servers"][0]["tool_configuration"]["allowed_tools"] == ["query_db"]


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


# --------------------------------------------------------------------------- #
# DÉFAUT 8 — une clé de SKIP_KEYS dont la valeur n'est PAS un scalaire
#
# SKIP_KEYS suppose que `type`, `id`, `name`, `cache_control`, `role`… portent
# une chaîne protocolaire. Rien ne le garantit : `cache_control` s'enrichit
# (`{"type": "ephemeral", "ttl": "5m"}`) et `metadata` est un dict LIBRE côté
# client. Un dict ou une liste sous une de ces clés est recopié VERBATIM, donc
# jamais soumis au détecteur : fail-open silencieux, la requête part en 200.
# --------------------------------------------------------------------------- #


def test_defaut8_sous_arbre_sous_une_cle_ignoree_est_substitue():
    body = {
        "model": "claude-opus-4",
        "system": [{
            "type": "text",
            "text": "contexte",
            # forme enrichie : `cache_control` n'est plus un dict à une clé
            "cache_control": {"type": "ephemeral", "annotation": "SECRET-HOST"},
        }],
        # `metadata` est libre : un client peut y poser une structure
        "metadata": {"type": {"host": "SECRET-HOST"}},
    }
    out = walk_request(body, marker_sub())
    brut = json.dumps(out)
    assert "SECRET-HOST" not in brut, (
        f"valeur réelle sortie sous une clé de SKIP_KEYS : {brut}")
    # le discriminant scalaire, lui, reste intact — il fait partie du protocole
    assert out["system"][0]["cache_control"]["type"] == "ephemeral"
    assert out["system"][0]["type"] == "text"


# --------------------------------------------------------------------------- #
# DÉFAUT 9 — `_is_known_control` admet TOUT scalaire
#
# `return True` sur une feuille scalaire fait passer n'importe quelle chaîne
# sous une clé de contrôle. `betas` est le pire cas : Anthropic ignore un nom
# de beta inconnu mais TRAITE la requête — la chaîne part et reste dans ses
# journaux, sans erreur visible côté opérateur.
# --------------------------------------------------------------------------- #


def test_defaut9_scalaire_sous_une_cle_de_controle_est_substitue():
    body = {
        "model": "claude-opus-4",
        "betas": ["SECRET-HOST"],
        "output_config": "cible SECRET-HOST",
        "thinking": {"type": "enabled", "budget_tokens": 1024},
        "messages": [{"role": "user", "content": "bonjour"}],
    }
    out = walk_request(body, marker_sub())
    brut = json.dumps(out)
    assert "SECRET-HOST" not in brut, (
        f"valeur réelle sortie sous une clé de contrôle : {brut}")


def test_defaut9_les_vrais_jetons_de_protocole_restent_intacts():
    """Le pendant : durcir ne doit pas corrompre les paramètres d'inférence."""
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {
        "model": "claude-sonnet-4-5-20250929",
        "anthropic_version": "2023-06-01",
        "betas": ["context-1m-2025-08-07", "fine-grained-tool-streaming-2025-05-14"],
        "service_tier": "auto",
        "max_tokens": 4096,
        "temperature": 0.7,
        "stream": True,
        "thinking": {"type": "enabled", "budget_tokens": 1024},
        "output_config": {"effort": "high"},
        "messages": [{"role": "user", "content": "bonjour"}],
    }
    out = walk_request(body, sabotage)
    for cle in ("model", "anthropic_version", "betas", "service_tier",
                "max_tokens", "temperature", "stream", "thinking", "output_config"):
        assert out[cle] == body[cle], f"paramètre de protocole corrompu : {cle}"


# --------------------------------------------------------------------------- #
# DÉFAUT 10 — mots-clés de JSON Schema substitués
#
# `type` sous sa forme UNION (`["string", "null"]`) n'était protégé que par
# hasard : SKIP_KEYS sautait la forme scalaire, jamais la liste. Substituer les
# mots-clés rend le schéma invalide et l'API répond 400 — session interrompue.
# `format` et `pattern` sont dans le même cas, en plus discret : `format` étant
# une annotation, l'API accepte `"format": "larch-cluster"` sans broncher.
# Observé en session RÉELLE (`tools.54.custom.input_schema`).
# --------------------------------------------------------------------------- #


def test_defaut10_les_mots_cles_de_schema_ne_sont_pas_substitues():
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {"tools": [{
        "name": "activate_window",
        "description": "focus une fenêtre",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_id": {"default": None, "type": ["string", "null"]},
                "pid": {"format": "int64", "minimum": 0,
                        "type": ["integer", "null"]},
            },
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "required": ["app_id"],
        },
    }]}
    schema = walk_request(body, sabotage)["tools"][0]["input_schema"]
    assert schema["type"] == "object"
    assert schema["properties"]["app_id"]["type"] == ["string", "null"]
    assert schema["properties"]["pid"]["type"] == ["integer", "null"]
    assert schema["properties"]["pid"]["format"] == "int64"
    assert schema["required"] == ["app_id"]
    assert schema["$schema"].startswith("https://json-schema.org/")


def test_defaut10_les_descriptions_restent_substituees():
    """Le pendant : c'est la fuite « la plus discrète » du plan §7."""
    body = {"tools": [{
        "name": "query",
        "description": "interroge SECRET-HOST",
        "input_schema": {
            "type": "object",
            "$defs": {
                # une définition nommée comme une clé de SKIP_KEYS
                "name": {"type": "string", "description": "hôte SECRET-HOST"},
            },
            "properties": {
                "host": {"type": "string", "description": "défaut SECRET-HOST"},
            },
        },
    }]}
    out = json.dumps(walk_request(body, marker_sub()))
    assert "SECRET-HOST" not in out, f"description non substituée : {out}"


def test_defaut8_la_forme_connue_de_cache_control_reste_verbatim():
    """`ttl` n'accepte que '5m' ou '1h' : le substituer donne une API 400.

    L'exclusion vaut pour la forme CONNUE seulement — c'est ce qui distingue
    « structure de protocole » de « recopie aveugle ».
    """
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {"system": [{"type": "text", "text": "x",
                        "cache_control": {"type": "ephemeral", "ttl": "5m"}}]}
    out = walk_request(body, sabotage)
    assert out["system"][0]["cache_control"] == {"type": "ephemeral", "ttl": "5m"}


# --------------------------------------------------------------------------- #
# DÉFAUT 11 — SKIP_KEYS appliqué aux DONNÉES UTILISATEUR
#
# SKIP_KEYS vaut à CHAQUE niveau de la traversée, y compris dans
# `tool_use.input` et `metadata`, où `name`, `id`, `type`, `role`, `data` sont
# des noms de paramètres parfaitement ordinaires (kubectl, Terraform, tout
# CRUD). Double effet : la valeur SORT en clair, et elle n'est pas RESTAURÉE au
# retour — l'outil s'exécute alors avec le nom fictif.
# Corollaire : dans un argument d'outil, `{"type": "thinking"}` n'est pas un
# bloc signé mais une valeur que n'importe qui peut écrire — l'opacité y était
# FORGEABLE.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cle", [
    "name", "id", "type", "role", "model", "data", "signature",
    "media_type", "stop_reason", "tool_use_id",
])
def test_defaut11_les_arguments_d_outil_sont_substitues(cle):
    body = {"messages": [{"role": "user", "content": [
        {"type": "tool_use", "id": "t1", "name": "kubectl",
         "input": {cle: "SECRET-HOST"}}]}]}
    sortie = json.dumps(walk_request(body, marker_sub()))
    assert "SECRET-HOST" not in sortie, f"input.{cle} sorti en clair : {sortie}"


@pytest.mark.parametrize("cle", ["id", "name", "role", "type", "user_id"])
def test_defaut11_metadata_est_un_dict_libre(cle):
    sortie = json.dumps(walk_request({"metadata": {cle: "SECRET-HOST"}}, marker_sub()))
    assert "SECRET-HOST" not in sortie, f"metadata.{cle} sorti en clair : {sortie}"


def test_defaut11_l_opacite_n_est_pas_forgeable_dans_un_argument():
    body = {"messages": [{"role": "user", "content": [
        {"type": "tool_use", "id": "t1", "name": "k",
         "input": {"payload": {"type": "thinking", "thinking": "SECRET-HOST"}}}]}]}
    sortie = json.dumps(walk_request(body, marker_sub()))
    assert "SECRET-HOST" not in sortie, f"opacité forgée : {sortie}"


def test_defaut11_les_vrais_blocs_thinking_restent_opaques():
    """Le pendant : dans `content`, `thinking` est signé (D3)."""
    bloc = {"type": "thinking", "thinking": "SECRET-HOST", "signature": "sig"}
    body = {"messages": [{"role": "assistant", "content": [bloc]}]}
    assert walk_request(body, marker_sub())["messages"][0]["content"][0] == bloc


def test_defaut11_l_outil_recoit_la_valeur_reelle():
    """Sans restauration, Claude Code exécuterait l'outil sur un hôte fictif."""
    sub = Substituter(to_surrogate=lambda s: s, surrogates={"fake-host": "vrai-host"})
    reponse = {"content": [{"type": "tool_use", "id": "t1", "name": "kubectl",
                            "input": {"name": "fake-host", "id": "fake-host"}}]}
    restaure, _ = walk_response(reponse, sub)
    assert restaure["content"][0]["input"] == {"name": "vrai-host", "id": "vrai-host"}
    # le nom de l'OUTIL, lui, reste le contrat passé au modèle
    assert restaure["content"][0]["name"] == "kubectl"


# --------------------------------------------------------------------------- #
# DÉFAUT 12 — surfaces de TEXTE rendues verbatim dans un JSON Schema
#
# `pattern` (une regex peut contraindre à un hôte précis), les CLÉS de
# `patternProperties` (ce sont des regex, pas des noms déclarés) et un `$ref`
# vers un schéma hébergé en interne portent tous des identifiants.
# --------------------------------------------------------------------------- #


def test_defaut12_les_surfaces_de_texte_du_schema_sont_substituees():
    body = {"tools": [{
        "name": "query", "description": "x",
        "input_schema": {
            "type": "object",
            "properties": {"h": {"type": "string", "pattern": "^srv-SECRET-HOST$"}},
            "patternProperties": {"^SECRET-HOST-[0-9]+$": {"type": "string"}},
            "$ref": "https://schemas.SECRET-HOST/creds.json",
        },
    }]}
    sortie = json.dumps(walk_request(body, marker_sub()))
    assert "SECRET-HOST" not in sortie, f"identifiant laissé dans le schéma : {sortie}"


def test_defaut12_les_references_locales_restent_intactes():
    """Le pendant : substituer une ancre casserait la résolution du schéma."""
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {"tools": [{
        "name": "q", "description": "x",
        "input_schema": {
            "type": "object",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "properties": {"u": {"$ref": "#/$defs/User"}},
            "$defs": {"User": {"type": "object"}},
        },
    }]}
    schema = walk_request(body, sabotage)["tools"][0]["input_schema"]
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["u"]["$ref"] == "#/$defs/User"


# --------------------------------------------------------------------------- #
# DÉFAUT 13 — SKIP_KEYS s'appliquait à TOUT dict imbriqué
#
# `USER_DATA_KEYS` protège `input` et `metadata`, mais un bloc `resource`
# renvoyé par un serveur MCP a la forme `{"type":…, "name":…, "uri":…}` : `name`
# y est une DONNÉE. Fuite sortante ET défaut de restauration au retour.
# `name` et `id` ne sont un contrat que dans un nœud de PROTOCOLE.
# --------------------------------------------------------------------------- #


def test_defaut13_un_nom_de_ressource_mcp_est_une_donnee():
    body = {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": [
            {"type": "resource", "name": "SECRET-HOST",
             "uri": "http://SECRET-HOST/"}]}]}]}
    sortie = json.dumps(walk_request(body, marker_sub()))
    assert "SECRET-HOST" not in sortie, f"nom de ressource sorti en clair : {sortie}"


def test_defaut13_le_nom_de_ressource_est_restaure():
    sub = Substituter(to_surrogate=lambda s: s, surrogates={"fake-host": "vrai-host"})
    reponse = {"content": [{"type": "tool_result", "tool_use_id": "t1", "content": [
        {"type": "resource", "name": "fake-host", "uri": "x"}]}]}
    restaure, _ = walk_response(reponse, sub)
    assert restaure["content"][0]["content"][0]["name"] == "vrai-host"


def test_defaut13_les_contrats_de_nom_restent_verbatim():
    """Le pendant : ces noms routent les appels d'outils."""
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {
        "tools": [{"name": "query_db", "description": "x",
                   "input_schema": {"type": "object"}}],
        "tool_choice": {"type": "tool", "name": "query_db"},
        "mcp_servers": [{"type": "url", "name": "infra", "url": "https://x/"}],
        "messages": [{"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "query_db", "input": {}}]}],
    }
    out = walk_request(body, sabotage)
    assert out["tools"][0]["name"] == "query_db"
    assert out["tool_choice"]["name"] == "query_db"
    assert out["mcp_servers"][0]["name"] == "infra"
    assert out["messages"][0]["content"][0]["name"] == "query_db"
    assert out["messages"][0]["content"][0]["id"] == "t1"


@pytest.mark.parametrize("media_type", [
    # `application/x-` et `application/vnd.` couvraient aussi du TEXTE.
    "application/x-yaml", "application/x-www-form-urlencoded",
    "application/vnd.api+json", "application/json", "text/plain",
])
def test_defaut13_les_media_types_texte_sont_traverses(media_type):
    body = {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "text", "media_type": media_type,
                                        "data": "hôte SECRET-HOST"}}]}]}
    sortie = json.dumps(walk_request(body, marker_sub()))
    assert "SECRET-HOST" not in sortie, f"{media_type} traité comme binaire"


@pytest.mark.parametrize("media_type", ["application/pdf", "image/png",
                                        "application/x-tar"])
def test_defaut13_les_media_types_binaires_restent_opaques(media_type):
    body = {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "base64", "media_type": media_type,
                                        "data": "AAAA"}}]}]}
    assert walk_request(body, marker_sub())["messages"][0]["content"][0]["source"]["data"] == "AAAA"


# --------------------------------------------------------------------------- #
# DÉFAUT 14 — entrées mal typées et vocabulaires trop permissifs
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("event", [
    {"type": "content_block_delta", "index": 0, "delta": None},
    {"type": "content_block_start", "index": 0, "content_block": None},
    {"type": "content_block_delta", "index": 0,
     "delta": {"type": "text_delta", "text": None}},
    {"type": "content_block_delta", "index": 0,
     "delta": {"type": "input_json_delta", "partial_json": None}},
])
def test_defaut14_un_evenement_sse_mal_type_ne_tue_pas_le_flux(event):
    """La génératrice mourait sans émettre d'`error` : flux perdu en silence."""
    from anthropic_walker import SSERewriter
    list(SSERewriter(marker_sub()).feed(event))  # ne doit pas lever


def test_defaut14_cache_control_a_un_vocabulaire_ferme():
    """`{"type": "db-prod01"}` passait : un nom d'hôte court est un jeton valide."""
    body = {"system": [{"type": "text", "text": "x",
                        "cache_control": {"type": "SECRET-HOST", "ttl": "5m"}}]}
    sortie = json.dumps(walk_request(body, marker_sub()))
    assert "SECRET-HOST" not in sortie, sortie


@pytest.mark.parametrize("cle, valeur", [
    ("$anchor", "Ancre"), ("$dynamicRef", "#meta"),
    ("dependentRequired", {"a": ["b"]}), ("dependencies", {"c": ["d"]}),
])
def test_defaut14_les_mots_cles_2020_12_sont_preserves(cle, valeur):
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {"tools": [{"name": "q", "description": "x",
                       "input_schema": {"type": "object", cle: valeur}}]}
    assert walk_request(body, sabotage)["tools"][0]["input_schema"][cle] == valeur


def test_defaut14_un_delta_signe_inconnu_reste_opaque():
    """D3 est un invariant verrouillé ; la restauration d'un delta inconnu non."""
    from anthropic_walker import SSERewriter
    sub = Substituter(to_surrogate=lambda s: s, surrogates={"fake": "vrai"})
    event = {"type": "content_block_delta", "index": 0,
             "delta": {"type": "redacted_thinking_delta", "data": "SIGNÉ_fake"}}
    assert list(SSERewriter(sub).feed(event)) == [event]


@pytest.mark.parametrize("corps", [None, [1, 2], "texte", 42])
def test_defaut14_un_corps_de_reponse_non_objet_leve_une_erreur_rattrapee(corps):
    with pytest.raises(ValueError):
        walk_response(corps, marker_sub())


def test_defaut14_message_start_est_restaure():
    from anthropic_walker import SSERewriter
    sub = Substituter(to_surrogate=lambda s: s, surrogates={"fake-host": "vrai-host"})
    event = {"type": "message_start", "message": {
        "id": "m1", "type": "message", "role": "assistant",
        "content": [{"type": "text", "text": "fake-host"}]}}
    sortie = list(SSERewriter(sub).feed(event))
    assert "vrai-host" in json.dumps(sortie)


def test_defaut14_un_identifiant_de_conteneur_scalaire_est_preserve():
    """Le substituer empêchait l'amont de réutiliser le conteneur."""
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    assert walk_request({"container": "container_abc123"}, sabotage)["container"] \
        == "container_abc123"


def test_defaut14_un_conteneur_en_objet_reste_traverse():
    body = {"container": {"image": "registry.SECRET-HOST/outils:1.0"}}
    assert "SECRET-HOST" not in json.dumps(walk_request(body, marker_sub()))


def test_defaut14_le_tampon_sse_est_borne():
    """Un amont sans séparateur faisait croître le tampon sans fin."""
    from anonproxy.sse import MAX_TAMPON, FluxSSEInvalide, iter_blocks
    with pytest.raises(FluxSSEInvalide):
        iter_blocks("x" * (MAX_TAMPON + 1), "")


# --------------------------------------------------------------------------- #
# DÉFAUT 15 — `_est_noeud_de_protocole` déduisait le protocole de la simple
# présence d'`input_schema`. Un serveur MCP renvoie ses définitions d'outils
# DANS un `tool_result` : `name` et `id` y sont des données.
# --------------------------------------------------------------------------- #


def test_defaut15_une_definition_d_outil_en_donnee_est_substituee():
    body = {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": [
            {"type": "tool_definition", "name": "SECRET-HOST", "id": "SECRET-HOST",
             "description": "x", "input_schema": {"type": "object"}}]}]}]}
    sortie = json.dumps(walk_request(body, marker_sub()))
    assert "SECRET-HOST" not in sortie, sortie


def test_defaut15_allowed_tools_est_herite_du_conteneur():
    """Deux crans sous `mcp_servers` : le drapeau doit se propager."""
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {"mcp_servers": [{"type": "url", "name": "infra", "url": "https://x/",
                             "tool_configuration": {"allowed_tools": ["query_db"]}}]}
    out = walk_request(body, sabotage)["mcp_servers"][0]
    assert out["tool_configuration"]["allowed_tools"] == ["query_db"]


def test_defaut15_le_texte_reste_emis_apres_un_stop_d_index_inconnu():
    """Le tampon restait accroché : l'opérateur perdait la fin du message."""
    from anthropic_walker import SSERewriter
    sub = Substituter(to_surrogate=lambda s: s, surrogates={"fake": "vrai"})
    rw = SSERewriter(sub)
    sortie = list(rw.feed({"type": "content_block_start", "index": 0,
                           "content_block": {"type": "text", "text": ""}}))
    sortie += list(rw.feed({"type": "content_block_delta", "index": 0,
                            "delta": {"type": "text_delta", "text": "vu fake"}}))
    sortie += list(rw.feed({"type": "content_block_stop", "index": 99}))
    sortie += list(rw.close())
    assert "vrai" in json.dumps(sortie)


def test_defaut15_un_json_accumule_sur_un_bloc_texte_n_est_pas_perdu():
    from anthropic_walker import SSERewriter
    sub = Substituter(to_surrogate=lambda s: s, surrogates={"fake": "vrai"})
    rw = SSERewriter(sub)
    sortie = list(rw.feed({"type": "content_block_start", "index": 0,
                           "content_block": {"type": "text", "text": ""}}))
    sortie += list(rw.feed({"type": "content_block_delta", "index": 0,
                            "delta": {"type": "input_json_delta",
                                      "partial_json": '{"h": "fake"}'}}))
    sortie += list(rw.feed({"type": "content_block_stop", "index": 0}))
    assert "vrai" in json.dumps(sortie)


# --------------------------------------------------------------------------- #
# DÉFAUT 16 — le drapeau « protocole » se propageait dans le SCHÉMA
#
# Posé par `tools`, il descendait jusqu'aux clés d'un `input_schema` autres que
# `properties` : `default`, `example`, `const` portent des valeurs d'exemple, où
# `name` et `id` sont des DONNÉES. Un schéma est structurel — aucun nom n'y est
# une clé de routage.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cle", ["default", "example", "examples", "const"])
def test_defaut16_les_exemples_d_un_schema_sont_des_donnees(cle):
    body = {"tools": [{
        "name": "query", "description": "x",
        "input_schema": {
            "type": "object",
            "properties": {"c": {"type": "string"}},
            cle: {"id": "SECRET-HOST", "name": "SECRET-HOST"},
        },
    }]}
    sortie = json.dumps(walk_request(body, marker_sub()))
    assert "SECRET-HOST" not in sortie, f"{cle} : {sortie}"


def test_defaut16_les_noms_de_routage_restent_verbatim():
    """Le pendant : hors schéma, ces noms routent les appels d'outils."""
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {
        "tools": [{"name": "query_db", "description": "x",
                   "input_schema": {"type": "object"}}],
        "tool_choice": {"type": "tool", "name": "query_db"},
        "mcp_servers": [{"type": "url", "name": "infra", "url": "https://x/",
                         "tool_configuration": {"allowed_tools": ["query_db"]}}],
    }
    out = walk_request(body, sabotage)
    assert out["tools"][0]["name"] == "query_db"
    assert out["tool_choice"]["name"] == "query_db"
    assert out["mcp_servers"][0]["name"] == "infra"
    assert out["mcp_servers"][0]["tool_configuration"]["allowed_tools"] == ["query_db"]


def test_defaut16_les_accumulateurs_sont_vides_avant_la_fin_du_message():
    """Émis APRÈS `message_stop`, ces deltas sont hors protocole : le client
    les ignore en silence, ou son parseur tombe."""
    from anthropic_walker import SSERewriter
    sub = Substituter(to_surrogate=lambda s: s, surrogates={"fake": "vrai"})
    rw = SSERewriter(sub)
    sortie = []
    for event in [
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "text_delta", "text": "vu fake"}},
        # pas de `content_block_stop` : le bloc reste ouvert
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {}},
        {"type": "message_stop"},
    ]:
        sortie += list(rw.feed(event))
    sortie += list(rw.close())

    types = [e["type"] for e in sortie]
    apres = types[types.index("message_stop"):]
    assert "content_block_delta" not in apres, f"delta après message_stop : {types}"
    # Le tampon de queue émet une partie du texte pendant le flux et le reste
    # au vidage : plusieurs deltas sont NORMAUX. Ce qui compte est le texte
    # reconstitué — ni perdu, ni dupliqué.
    texte = "".join(e["delta"]["text"] for e in sortie
                    if e["type"] == "content_block_delta"
                    and e["delta"].get("type") == "text_delta")
    assert texte == "vu vrai", f"texte reconstitué : {texte!r}"


@pytest.mark.parametrize("corps", [[], None, 123, "texte"])
def test_defaut16_un_corps_de_requete_non_objet_leve_une_erreur_rattrapee(corps):
    with pytest.raises(ValueError):
        walk_request(corps, marker_sub())


# --------------------------------------------------------------------------- #
# DÉFAUT 17 — l'opacité était forgeable partout SAUF dans les données
# utilisateur. Un bloc signé n'est produit que par l'API et ne revient que dans
# le `content` d'un message ASSISTANT ; ailleurs, `type` est une valeur qu'un
# client ou un serveur MCP écrit lui-même. Le sous-arbre entier sortait alors
# VERBATIM, sans entrée de coffre ni substitut non résolu pour le signaler.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("nom, body", [
    ("message utilisateur", {"messages": [{"role": "user", "content": [
        {"type": "thinking", "thinking": "hôte SECRET-HOST", "signature": "x"}]}]}),
    # Le vecteur le plus grave : un serveur MCP hostile renvoie un bloc
    # `thinking`, Claude Code le réémet dans un `tool_result` au tour suivant.
    ("sortie d'outil", {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "tu_1", "content": [
            {"type": "thinking", "thinking": "hôte SECRET-HOST"}]}]}]}),
    ("sortie d'outil, bloc masqué", {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "tu_1", "content": [
            {"type": "redacted_thinking", "data": "hôte SECRET-HOST"}]}]}]}),
    ("prompt système", {"system": [
        {"type": "thinking", "thinking": "hôte SECRET-HOST"}]}),
    ("définition d'outil", {"tools": [{"name": "t", "description": [
        {"type": "thinking", "thinking": "hôte SECRET-HOST"}]}]}),
])
def test_defaut17_l_opacite_n_est_legitime_que_dans_un_message_assistant(nom, body):
    assert "SECRET-HOST" not in json.dumps(walk_request(body, marker_sub())), nom


def test_defaut17_un_bloc_signe_d_assistant_reste_intact():
    """Contrôle D3 : là où il est légitime, le bloc n'est pas touché."""
    body = {"messages": [{"role": "assistant", "content": [
        {"type": "thinking", "thinking": "SECRET-HOST", "signature": "sig-abc"}]}]}
    bloc = walk_request(body, marker_sub())["messages"][0]["content"][0]
    assert bloc == {"type": "thinking", "thinking": "SECRET-HOST",
                    "signature": "sig-abc"}


def test_defaut17_la_restauration_ne_touche_aucun_bloc_signe():
    """Au RETOUR le risque s'inverse : traverser invaliderait la signature."""
    body = {"role": "assistant", "type": "message", "content": [
        {"type": "thinking", "thinking": "fake-host", "signature": "sig"},
        {"type": "tool_use", "id": "tu_1", "name": "run",
         "input": {"host": "fake-host"}},
    ]}
    resolved, _ = walk_response(body, Substituter(
        to_surrogate=lambda s: s, surrogates={"fake-host": "SECRET-HOST"}))
    assert resolved["content"][0]["thinking"] == "fake-host"
    assert resolved["content"][1]["input"]["host"] == "SECRET-HOST"


# --------------------------------------------------------------------------- #
# DÉFAUT 18 — la légitimité d'un bloc signé était déduite du dict COURANT
#
# Le correctif du défaut 17 testait `node.get("role") == "assistant"`. N'importe
# quel dict imbriqué portant ce rôle obtenait donc l'opacité pour son `content`
# — y compris à l'intérieur d'un `tool_result`, dont le contenu vient d'un
# serveur MCP. La propriété était RÉTRÉCIE, pas supprimée : elle est passée de
# « tout dict de type thinking » à « tout dict de rôle assistant ».
#
# La légitimité est une propriété de POSITION : elle se descend depuis la
# racine `messages`, elle ne se déduit pas d'un nœud isolé.
# --------------------------------------------------------------------------- #

_FAUX_MESSAGE = {"role": "assistant", "content": [
    {"type": "thinking", "thinking": "hôte SECRET-HOST", "signature": "forgée"}]}


@pytest.mark.parametrize("nom, body", [
    ("sortie d'outil", {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "tu_1",
         "content": [_FAUX_MESSAGE]}]}]}),
    ("champ libre d'un bloc", {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "ok", "extra": _FAUX_MESSAGE}]}]}),
    ("sous mcp_servers", {"mcp_servers": [
        {"name": "srv", "tool_configuration": _FAUX_MESSAGE}]}),
    ("imbriqué en profondeur", {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t",
         "content": [{"type": "text", "a": {"b": _FAUX_MESSAGE}}]}]}]}),
    ("bloc masqué forgé", {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t", "content": [
            {"role": "assistant", "content": [
                {"type": "redacted_thinking", "data": "hôte SECRET-HOST"}]}]}]}]}),
])
def test_defaut18_un_faux_message_assistant_imbrique_ne_rend_rien_opaque(nom, body):
    assert "SECRET-HOST" not in json.dumps(walk_request(body, marker_sub())), nom


def test_defaut18_un_vrai_message_assistant_reste_opaque():
    """Contrôle : la position légitime, elle, doit continuer de fonctionner."""
    body = {"messages": [
        {"role": "user", "content": [{"type": "text", "text": "salut"}]},
        {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "SECRET-HOST", "signature": "sig"},
            {"type": "text", "text": "vu SECRET-HOST"}]},
    ]}
    sortie = walk_request(body, marker_sub())["messages"][1]["content"]
    assert sortie[0] == {"type": "thinking", "thinking": "SECRET-HOST",
                         "signature": "sig"}
    # et le texte voisin, lui, est bien substitué
    assert "SECRET-HOST" not in sortie[1]["text"]


# --------------------------------------------------------------------------- #
# DÉFAUT 19 — une sous-clé inattendue faisait substituer les clés CONNUES
#
# `cache_control` n'était recopié que si TOUTE sa forme était connue ; sinon il
# passait en mode données, et `type` — qui n'accepte que `ephemeral` — était
# substitué. Un champ ajouté demain à côté suffisait à faire refuser la requête
# entière (400).
# --------------------------------------------------------------------------- #


def test_defaut19_une_sous_cle_inconnue_ne_casse_pas_le_contrat():
    body = {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "salut",
         "cache_control": {"type": "ephemeral", "ttl": "5m",
                           "champ_futur": "SECRET-HOST"}}]}]}
    cc = walk_request(body, marker_sub())["messages"][0]["content"][0]["cache_control"]
    assert cc["type"] == "ephemeral" and cc["ttl"] == "5m"
    # le champ inconnu, lui, reste traversé : c'est de la donnée
    assert "SECRET-HOST" not in cc["champ_futur"]


# --------------------------------------------------------------------------- #
# DÉFAUT 20 — un type d'événement SSE inconnu perdait la restauration
#
# La branche par défaut rendait l'événement verbatim : ses substituts
# arrivaient non résolus. L'opérateur voyait le nom FICTIF, et un outil s'y
# serait exécuté. Un type inconnu est justement celui qu'aucun test ne couvre.
# --------------------------------------------------------------------------- #


def test_defaut20_un_evenement_sse_inconnu_est_restaure():
    from anthropic_walker import SSERewriter

    sub = Substituter(to_surrogate=lambda s: s,
                      surrogates={"fake-host-01": "db-01.acme.internal"})
    sortie = list(SSERewriter(sub).feed(
        {"type": "container_upload_complete",
         "container": {"host": "fake-host-01"}}))
    assert sortie[0]["container"]["host"] == "db-01.acme.internal"


def test_defaut20_un_ping_reste_intact():
    from anthropic_walker import SSERewriter

    sub = Substituter(to_surrogate=lambda s: s, surrogates={})
    assert list(SSERewriter(sub).feed({"type": "ping"})) == [{"type": "ping"}]


# --------------------------------------------------------------------------- #
# DÉFAUT 21 — toute clé de protocole était recopiée SANS CONDITION
#
# `name` et `id` avaient été cadrés au round 4 ; les autres non. Un tiers —
# serveur MCP, tool_result manipulé — plaçait `{"type": "text", "role": "<hôte
# réel>"}` dans son sous-arbre et la valeur sortait verbatim. Et le caractère
# « protocolaire » d'un nœud se DÉDUISAIT de son propre `type` : écrire
# `{"type": "tool_use", "name": …}` suffisait à obtenir la protection.
#
# Chaque clé est désormais gardée soit par sa POSITION, soit par la FORME de sa
# valeur : un nom d'hôte n'a jamais l'air d'un rôle ni d'un type de bloc.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cle", [
    "signature", "tool_use_id", "stop_reason", "role", "model", "media_type",
])
def test_defaut21_une_cle_de_protocole_posee_ailleurs_est_traversee(cle):
    body = {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "ok", cle: "SECRET-HOST"}]}]}
    assert "SECRET-HOST" not in json.dumps(walk_request(body, marker_sub())), cle


@pytest.mark.parametrize("btype", [
    "tool_use", "server_tool_use", "mcp_tool_use", "message",
])
def test_defaut21_le_type_du_noeud_ne_confere_plus_le_statut_de_protocole(btype):
    body = {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "tu", "content": [
            {"type": btype, "name": "SECRET-HOST", "id": "id-SECRET-HOST"}]}]}]}
    assert "SECRET-HOST" not in json.dumps(walk_request(body, marker_sub())), btype


def test_defaut21_les_contrats_legitimes_restent_verbatim():
    """Contrôle : substituer ces valeurs-là casserait le routage de l'outil."""
    body = {"messages": [
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_01", "name": "query_db",
             "input": {"host": "SECRET-HOST"}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_01",
             "content": [{"type": "text", "text": "vu SECRET-HOST"}]}]},
    ]}
    sortie = walk_request(body, marker_sub())
    outil = sortie["messages"][0]["content"][0]
    assert outil["name"] == "query_db" and outil["id"] == "toolu_01"
    assert sortie["messages"][1]["content"][0]["tool_use_id"] == "toolu_01"
    # …et les données, elles, sont bien substituées
    assert outil["input"]["host"] != "SECRET-HOST"
    assert "SECRET-HOST" not in json.dumps(sortie["messages"][1])


# --------------------------------------------------------------------------- #
# DÉFAUT 22 — `type: "base64"` disait comment la charge est ENCODÉE, pas ce
# qu'elle contient. Un document texte encodé (JSON, YAML, CSV — le geste
# ordinaire « colle-moi ce fichier ») partait ENTIER vers l'API.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("media", ["text/plain", "text/csv", "application/json",
                                   "application/yaml", "text/markdown"])
def test_defaut22_un_document_texte_encode_est_pseudonymise(media):
    import base64 as b64
    charge = b64.b64encode(b'{"host": "SECRET-HOST"}').decode()
    body = {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "base64", "media_type": media,
                                        "data": charge}}]}]}
    rendu = walk_request(body, marker_sub())["messages"][0]["content"][0]["source"]
    assert "SECRET-HOST" not in b64.b64decode(rendu["data"]).decode(), media


@pytest.mark.parametrize("media", ["image/png", "application/pdf"])
def test_defaut22_une_charge_binaire_reste_intacte(media):
    import base64 as b64
    charge = b64.b64encode(bytes(range(256))).decode()
    body = {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "base64", "media_type": media,
                                        "data": charge}}]}]}
    rendu = walk_request(body, marker_sub())["messages"][0]["content"][0]["source"]
    assert rendu["data"] == charge, media


# --------------------------------------------------------------------------- #
# DÉFAUT 23 — le round précédent ne couvrait que l'UTF-8, et ne regardait la
# charge que sous `type: "base64"`.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("encodage", ["latin-1", "cp1252", "utf-16", "utf-16-le"])
def test_defaut23_une_charge_texte_non_utf8_est_pseudonymisee(encodage):
    """Un CSV Windows en UTF-16, un log latin-1 : la charge sortait ENTIÈRE."""
    import base64 as b64
    brut = f"connexion vers SECRET-HOST depuis Genève".encode(encodage)
    body = {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {
            "type": "base64", "media_type": "text/plain",
            "data": b64.b64encode(brut).decode()}}]}]}
    rendu = walk_request(body, marker_sub())["messages"][0]["content"][0]["source"]
    assert b"SECRET-HOST" not in b64.b64decode(rendu["data"]), encodage
    assert "SECRET-HOST".encode(encodage) not in b64.b64decode(rendu["data"])


@pytest.mark.parametrize("btype", ["resource", "text", "custom_payload"])
def test_defaut23_une_charge_encodee_sous_un_autre_type_est_vue(btype):
    """Un serveur MCP place `data` sous n'importe quel type de bloc."""
    import base64 as b64
    charge = b64.b64encode(b"connexion vers SECRET-HOST").decode()
    body = {"messages": [{"role": "user", "content": [
        {"type": btype, "data": charge}]}]}
    rendu = walk_request(body, marker_sub())["messages"][0]["content"][0]["data"]
    assert b"SECRET-HOST" not in b64.b64decode(rendu), btype


def test_defaut23_une_charge_reellement_binaire_reste_intacte():
    import base64 as b64
    charge = b64.b64encode(bytes(range(256))).decode()
    body = {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {
            "type": "base64", "media_type": "image/png", "data": charge}}]}]}
    rendu = walk_request(body, marker_sub())["messages"][0]["content"][0]["source"]
    assert rendu["data"] == charge


# --------------------------------------------------------------------------- #
# DÉFAUT 24 — routage : un bloc de résultat d'outil SERVEUR porte lui aussi un
# `tool_use_id`, et un bloc MCP porte le nom de son serveur.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("btype", [
    "web_search_tool_result", "code_execution_tool_result",
])
def test_defaut24_le_tool_use_id_d_un_resultat_serveur_ne_diverge_pas(btype):
    body = {"messages": [{"role": "assistant", "content": [
        {"type": "server_tool_use", "id": "srvtoolu_SECRET-HOST",
         "name": "web_search"},
        {"type": btype, "tool_use_id": "srvtoolu_SECRET-HOST", "content": []},
    ]}]}
    blocs = walk_request(body, marker_sub())["messages"][0]["content"]
    assert blocs[0]["id"] == blocs[1]["tool_use_id"], btype


def test_defaut24_le_nom_de_serveur_mcp_suit_son_entree():
    """`mcp_servers[].name` reste verbatim : `server_name` doit le suivre."""
    body = {
        "mcp_servers": [{"type": "url", "name": "mcp-SECRET-HOST",
                         "url": "https://interne/mcp"}],
        "messages": [{"role": "assistant", "content": [
            {"type": "mcp_tool_use", "id": "t1", "name": "q",
             "server_name": "mcp-SECRET-HOST"}]}],
    }
    sortie = walk_request(body, marker_sub())
    assert (sortie["mcp_servers"][0]["name"]
            == sortie["messages"][0]["content"][0]["server_name"])


# --------------------------------------------------------------------------- #
# DÉFAUT 25 — les vocabulaires fermés étaient trop larges, et un `id` de
# message n'est pas un contrat.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cle, valeur", [
    # `command` et `titan` sont des mots anglais : la forme les acceptait comme
    # préfixes de modèle, et l'insensibilité à la casse élargissait encore.
    ("model", "commander-billing-prod-01"),
    ("model", "TITAN-CORP-VAULT"),
    # un segment purement numérique signe une convention de nom d'hôte
    ("type", "srv_billing_01"),
    # le type de premier niveau d'un media est un registre FERMÉ
    ("media_type", "srv-billing-prod-01/acme-internal"),
])
def test_defaut25_un_vocabulaire_ferme_ne_laisse_pas_passer_un_hote(cle, valeur):
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "ok", cle: valeur}]}]}
    rendu = walk_request(body, sabotage)["messages"][0]["content"][0]
    assert rendu[cle] != valeur, f"{cle}={valeur} rendu verbatim"


@pytest.mark.parametrize("cle, valeur", [
    ("role", "developer"),
    ("stop_reason", "content_filter"),
    ("stop_reason", "length"),
    # les paramètres RFC 6838 sont valides et doivent passer
    ("media_type", "text/plain; charset=utf-8"),
    ("type", "web_search_tool_result"),
    ("type", "base64"),
    ("model", "claude-opus-4-20250514"),
])
def test_defaut25_une_valeur_reelle_de_l_api_reste_verbatim(cle, valeur):
    """Une forme trop stricte substitue une valeur légitime : 400, panne dure."""
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "ok", cle: valeur}]}]}
    rendu = walk_request(body, sabotage)["messages"][0]["content"][0]
    assert rendu[cle] == valeur, f"{cle}={valeur} substitué"


def test_defaut25_un_id_de_message_n_est_pas_un_contrat():
    body = {"messages": [{"role": "user", "id": "SECRET-HOST", "content": "x"}]}
    assert "SECRET-HOST" not in json.dumps(walk_request(body, marker_sub()))


# --------------------------------------------------------------------------- #
# DÉFAUT 26 — j'avais fermé le type de PREMIER niveau d'un `media_type` et
# laissé le SOUS-TYPE accepter les points. `text/db-01.acme.internal` en avait
# donc la forme, et sortait verbatim — sans entrée de coffre ni substitut non
# résolu pour le signaler. Même classe que la règle d'extensions du round 8 :
# une règle de forme qui rend des valeurs PUBLIQUES échoue en silence.
# --------------------------------------------------------------------------- #


def _media(valeur):
    return {"messages": [{"role": "user", "content": [
        {"type": "image", "media_type": valeur, "text": "x"}]}]}


@pytest.mark.parametrize("valeur", [
    "text/db-01.acme.internal",
    "image/x-acme-registry.acme.corp",
    "multipart/form-data; boundary=db-01.acme.internal",
    "text/plain; charset=db-01.acme.internal",
])
def test_defaut26_un_media_type_ne_porte_pas_d_hote(valeur):
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    rendu = walk_request(_media(valeur), sabotage)["messages"][0]["content"][0]
    assert rendu["media_type"] != valeur, f"{valeur} rendu verbatim"


@pytest.mark.parametrize("valeur", [
    "text/plain", "image/png", "application/json", "application/vnd.api+json",
    "application/vnd.google-earth.kml+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain; charset=utf-8", "multipart/form-data; boundary=abc123",
    "application/x-yaml", "text/markdown",
])
def test_defaut26_un_media_type_reel_reste_verbatim(valeur):
    """Le substituer fait refuser la requête entière."""
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    rendu = walk_request(_media(valeur), sabotage)["messages"][0]["content"][0]
    assert rendu["media_type"] == valeur, f"{valeur} substitué"


def test_defaut26_residu_l_arbre_vendeur_reste_dotte():
    """Résidu ASSUMÉ : un arbre vendeur est pointé PAR NATURE.

    `application/vnd.<vendeur>.<produit>` a la même forme qu'un arbre
    contenant un hôte. Le distinguer demanderait de savoir que `acme` est à
    nous — une question d'INVENTAIRE, pas de forme. Même arbitrage que les
    paquets Java sous un préfixe tiers.
    """
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    valeur = "application/vnd.acme.db-01.acme.internal+json"
    rendu = walk_request(_media(valeur), sabotage)["messages"][0]["content"][0]
    assert rendu["media_type"] == valeur


# --------------------------------------------------------------------------- #
# DÉFAUT 27 — le protocole MCP écrit `mimeType`, pas `media_type` ; et un
# `file_id` désigne un fichier DÉJÀ téléversé.
# --------------------------------------------------------------------------- #


def test_defaut27_une_charge_binaire_declaree_en_mimeType_reste_intacte():
    """Ne lire que `media_type` faisait prendre un petit binaire pour du texte,
    donc le décoder, le substituer et le ré-encoder — corrompu."""
    import base64 as b64
    charge = b64.b64encode(bytes([0x89, 0x50, 0x4E, 0x47, 0x41, 0x42])).decode()
    body = {"messages": [{"role": "user", "content": [
        {"type": "resource", "mimeType": "image/png", "data": charge}]}]}
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    assert walk_request(body, sabotage)["messages"][0]["content"][0]["data"] == charge


def test_defaut27_un_file_id_designe_un_fichier_deja_televerse():
    """Le substituer donne un identifiant qui ne correspond à rien : 404."""
    sabotage = Substituter(to_surrogate=lambda s: "SABOTÉ")
    body = {"messages": [{"role": "user", "content": [
        {"type": "container_upload", "file_id": "file_xyz789"}]}]}
    rendu = walk_request(body, sabotage)["messages"][0]["content"][0]
    assert rendu["file_id"] == "file_xyz789"


def test_defaut27_un_file_id_hors_position_reste_une_donnee():
    body = {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "ok", "file_id": "SECRET-HOST"}]}]}
    assert "SECRET-HOST" not in json.dumps(walk_request(body, marker_sub()))


@pytest.mark.parametrize("forme,attendu_verbatim", [
    ({"carte": ["adresse"]}, True),      # liste de NOMS : un contrat
    ({"carte": {"properties": {"adresse": {
        "type": "string",
        "description": "adresse hebergee sur SECRET-HOST"}}}}, False),
    # TROISIEME forme, que le correctif « union » avait lui-meme manquee : une
    # liste qui ne contient PAS que des noms. Se fier au type `list` sans
    # regarder son contenu laissait passer un dict glisse dedans, avec ses
    # valeurs, sans que le walker le voie.
    ({"carte": ["adresse", {"hote": "db-01.SECRET-HOST"}]}, False),
    ({"carte": [{"description": "point interne sur SECRET-HOST"}]}, False),
])
def test_defaut_dependencies_accepte_DEUX_formes(forme, attendu_verbatim):
    """HAUT, fuite silencieuse — `dependencies` est une UNION, pas une liste.

    En JSON Schema draft-04/06/07, la valeur de `dependencies` est soit une
    liste de NOMS de proprietes (un contrat : le substituer casserait la
    correspondance en silence), soit un SOUS-SCHEMA entier. Le walker la
    classait structurelle dans les deux cas, donc descriptions, defauts et enums
    de la seconde forme sortaient VERBATIM — et le walker ne voyait meme pas le
    texte, donc aucune entree au coffre et rien a compter.

    Le decoupage moderne (`dependentRequired` pour les listes,
    `dependentSchemas` pour les schemas) date de 2019-09 : tout outil genere
    depuis une OpenAPI 3.0, basee sur draft-04, emet la forme qui fuit.
    """
    corps = {"model": "m", "messages": [], "tools": [{
        "name": "t", "description": "d",
        "input_schema": {"type": "object",
                         "properties": {"carte": {"type": "string"}},
                         "dependencies": forme}}]}
    rendu = json.dumps(walk_request(corps, marker_sub()), ensure_ascii=False)
    if attendu_verbatim:
        assert '["adresse"]' in rendu, rendu
    else:
        assert "SECRET-HOST" not in rendu, rendu
        assert "fake-host" in rendu, rendu


@pytest.mark.parametrize("litterale", ["default", "const", "example", "examples"])
@pytest.mark.parametrize("interne", ["type", "format", "required", "$anchor",
                                     "dependentRequired"])
def test_defaut_une_valeur_litterale_n_est_pas_un_sous_schema(litterale, interne):
    """HAUT, fuite silencieuse — la JUMELLE exacte de la branche `enum`.

    `default`, `const`, `example` et `examples` portent une VALEUR que le modele
    doit emettre, jamais un fragment de schema : les cles qu'elle contient sont
    celles de la structure de l'operateur. En y propageant `in_schema`, les cles
    structurelles y etaient rendues VERBATIM — et le walker ne voyait meme pas
    le texte, donc aucune entree au coffre et rien a compter.

    La branche `enum` traite deja ses membres en mode DONNEES pour cette raison
    exacte, quelques lignes plus haut. Les `default` objets sont partout dans un
    schema genere depuis une OpenAPI : CRD Kubernetes, provider Terraform.
    """
    corps = {"model": "m", "messages": [], "tools": [{
        "name": "t", "description": "d",
        "input_schema": {"type": "object", "properties": {"conf": {
            "type": "object", litterale: {interne: "SECRET-HOST"}}}}}]}
    rendu = json.dumps(walk_request(corps, marker_sub()), ensure_ascii=False)
    assert "SECRET-HOST" not in rendu, rendu
    assert "fake-host" in rendu, rendu
