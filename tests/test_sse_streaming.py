"""Phase 3 TEST-FIRST — streaming SSE et traversée du walker (D2, D3, D5).

Ces trois-là « ne se déboguent pas après coup » : substitut coupé entre deux
chunks, arguments d'outils jamais résolus en flux, blocs thinking opaques.

Le walker (`anthropic_walker.py`) est fourni : ces tests le mettent à
l'épreuve tel quel, ainsi que son câblage dans le proxy.
Données 100 % synthétiques.
"""
from __future__ import annotations

import json

import pytest


from anthropic_walker import (
    SSERewriter,
    Substituter,
    walk_request,
    walk_response,
)

# substitut → réel (table de restauration synthétique)
SURROGATES = {
    "cluster-01-prod.northwind.internal": "db-master-01-prod.acme.internal",
    "10.42.7.13": "10.1.2.3",
    "billing-api": "payments-api",
}


def make_sub(to_surrogate=lambda s: s) -> Substituter:
    return Substituter(to_surrogate=to_surrogate, surrogates=dict(SURROGATES))


def deltas(events: list[dict]) -> str:
    """Concatène le texte émis par les text_delta."""
    return "".join(
        e["delta"]["text"]
        for e in events
        if e.get("type") == "content_block_delta" and e["delta"].get("type") == "text_delta"
    )


def run_stream(sub: Substituter, events: list[dict]) -> tuple[list[dict], list[str]]:
    rw = SSERewriter(sub)
    out: list[dict] = []
    for ev in events:
        out.extend(rw.feed(ev))
    return out, rw.unresolved


def text_stream(chunks: list[str]) -> list[dict]:
    ev = [{"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}]
    ev += [{"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": c}} for c in chunks]
    ev.append({"type": "content_block_stop", "index": 0})
    return ev


# --------------------------------------------------------------------------- #
# Substitut coupé entre chunks SSE (le scénario adversarial du plan §5)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cut", range(1, len("cluster-01-prod.northwind.internal")))
def test_substitut_coupe_entre_chunks_toutes_positions(cut):
    """Quelle que soit la position de coupe, la valeur réelle est restaurée."""
    surrogate = "cluster-01-prod.northwind.internal"
    sub = make_sub()
    events = text_stream(["Hôte ", surrogate[:cut], surrogate[cut:], " est joignable."])
    out, unresolved = run_stream(sub, events)
    assert deltas(out) == "Hôte db-master-01-prod.acme.internal est joignable."
    assert unresolved == []


def test_substitut_coupe_caractere_par_caractere():
    surrogate = "10.42.7.13"
    sub = make_sub()
    out, _ = run_stream(sub, text_stream(list(f"ping {surrogate} ok")))
    assert deltas(out) == "ping 10.1.2.3 ok"


def test_aucune_perte_de_texte_sans_substitut():
    sub = make_sub()
    chunks = ["Rien ", "de ", "sensible ", "ici."]
    out, _ = run_stream(sub, text_stream(chunks))
    assert deltas(out) == "".join(chunks)


def test_flush_final_emet_le_reste():
    """Le tail buffer ne doit rien retenir après content_block_stop."""
    sub = make_sub()
    out, _ = run_stream(sub, text_stream(["fin de message court"]))
    assert deltas(out) == "fin de message court"


# --------------------------------------------------------------------------- #
# D2 — arguments d'outils : aucune résolution pendant le streaming
# --------------------------------------------------------------------------- #


def test_partial_json_jamais_emis_pendant_le_stream():
    sub = make_sub()
    payload = {"host": "cluster-01-prod.northwind.internal", "port": 5432}
    raw = json.dumps(payload)
    events = [
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "tool_use", "id": "toolu_1", "name": "psql", "input": {}}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "input_json_delta", "partial_json": raw[:12]}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "input_json_delta", "partial_json": raw[12:]}},
        {"type": "content_block_stop", "index": 0},
    ]
    # D2 : tant que le bloc n'est pas fermé, RIEN ne sort — c'est l'invariant.
    # (Au stop, le delta atomique est légitimement émis avant l'événement stop :
    #  c'est l'ordre SSE correct.)
    rw = SSERewriter(sub)
    out: list[dict] = []
    for ev in events:
        emitted_now = list(rw.feed(ev))
        if ev.get("delta", {}).get("type") == "input_json_delta":
            assert emitted_now == [], "des arguments partiels ont été émis en flux"
        out.extend(emitted_now)

    emitted = [e for e in out
               if e.get("delta", {}).get("type") == "input_json_delta"]
    assert len(emitted) == 1, "les arguments doivent être émis en UN delta atomique"
    resolved = json.loads(emitted[0]["delta"]["partial_json"])
    assert resolved == {"host": "db-master-01-prod.acme.internal", "port": 5432}


def test_json_invalide_renvoye_brut_et_signale():
    sub = make_sub()
    events = [
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "tool_use", "id": "t", "name": "x", "input": {}}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "input_json_delta", "partial_json": '{"host": "clus'}},
        {"type": "content_block_stop", "index": 0},
    ]
    out, unresolved = run_stream(sub, events)
    assert "<json_invalide>" in unresolved
    emitted = [e for e in out if e.get("delta", {}).get("type") == "input_json_delta"]
    assert emitted[0]["delta"]["partial_json"] == '{"host": "clus'


def test_valeurs_imbriquees_dans_tool_use_resolues():
    sub = make_sub()
    payload = {"spec": {"hosts": ["cluster-01-prod.northwind.internal", "10.42.7.13"],
                        "repo": "billing-api"}}
    raw = json.dumps(payload)
    events = [
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "tool_use", "id": "t", "name": "apply", "input": {}}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "input_json_delta", "partial_json": raw}},
        {"type": "content_block_stop", "index": 0},
    ]
    out, _ = run_stream(sub, events)
    emitted = [e for e in out if e.get("delta", {}).get("type") == "input_json_delta"][0]
    got = json.loads(emitted["delta"]["partial_json"])
    assert got["spec"]["hosts"] == ["db-master-01-prod.acme.internal", "10.1.2.3"]
    assert got["spec"]["repo"] == "payments-api"


# --------------------------------------------------------------------------- #
# D3 — thinking / redacted_thinking strictement opaques
# --------------------------------------------------------------------------- #


def test_thinking_delta_passthrough_intact():
    sub = make_sub()
    signed = "cluster-01-prod.northwind.internal apparaît ici mais NE DOIT PAS bouger"
    events = [
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "thinking", "thinking": "", "signature": "sig"}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "thinking_delta", "thinking": signed}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "signature_delta", "signature": "abc123"}},
        {"type": "content_block_stop", "index": 0},
    ]
    out, _ = run_stream(sub, events)
    assert out[1]["delta"]["thinking"] == signed
    assert out[2]["delta"]["signature"] == "abc123"


def test_thinking_non_streame_intact():
    sub = make_sub()
    body = {"content": [
        {"type": "thinking", "thinking": "cluster-01-prod.northwind.internal", "signature": "s"},
        {"type": "text", "text": "hôte cluster-01-prod.northwind.internal"},
    ]}
    out, _ = walk_response(body, sub)
    assert out["content"][0]["thinking"] == "cluster-01-prod.northwind.internal"
    assert out["content"][1]["text"] == "hôte db-master-01-prod.acme.internal"


# --------------------------------------------------------------------------- #
# D5 — fail-closed : substitut inventé jamais deviné
# --------------------------------------------------------------------------- #


def test_substitut_halluciné_non_resolu():
    sub = make_sub()
    out, _ = run_stream(sub, text_stream(["essai sur cluster-02-prod.northwind.internal"]))
    # 'cluster-02-...' n'est pas dans la table : préfixe connu, mais jamais deviné
    assert "cluster-02-prod.northwind.internal" in deltas(out)
    assert "acme" not in deltas(out)


def test_walk_response_strict_leve_si_inconnu():
    from anthropic_walker import UnresolvedSurrogate

    sub = Substituter(to_surrogate=lambda s: s, surrogates={})
    body = {"content": [{"type": "text", "text": "rien"}]}
    out, unresolved = walk_response(body, sub, strict=True)  # table vide : rien à résoudre
    assert unresolved == []
    assert out == body


# --------------------------------------------------------------------------- #
# Sens sortant : les quatre surfaces (system, messages, tools, metadata)
# --------------------------------------------------------------------------- #


def upper_marker(s: str) -> str:
    """to_surrogate factice : marque le passage du walker."""
    return s.replace("SECRET-HOST", "fake-host")


def test_walk_request_couvre_les_quatre_surfaces():
    sub = make_sub(to_surrogate=upper_marker)
    body = {
        "model": "claude-fable-5",
        "system": [{"type": "text", "text": "cluster SECRET-HOST", "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {"role": "user", "content": "sur SECRET-HOST"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "bash",
                 "input": {"command": "ssh SECRET-HOST"}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "depuis SECRET-HOST"},
            ]},
        ],
        "tools": [{
            "name": "query_db",
            "description": "interroge SECRET-HOST",
            "input_schema": {
                "type": "object",
                "properties": {"host": {"type": "string", "description": "hôte SECRET-HOST"}},
                "required": ["host"],
            },
        }],
        "metadata": {"user_id": "SECRET-HOST"},
    }
    out = walk_request(body, sub)
    blob = json.dumps(out)
    assert "SECRET-HOST" not in blob, "fuite : une surface n'a pas été traitée"
    assert out["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert out["tools"][0]["name"] == "query_db", "le nom d'outil est un contrat, pas une donnée"
    assert out["tools"][0]["input_schema"]["required"] == ["host"]
    assert "host" in out["tools"][0]["input_schema"]["properties"]
    assert out["model"] == "claude-fable-5"


def test_walk_request_traite_tout_l_historique():
    sub = make_sub(to_surrogate=upper_marker)
    body = {"messages": [{"role": "user", "content": f"tour {i} SECRET-HOST"} for i in range(20)]}
    out = walk_request(body, sub)
    assert "SECRET-HOST" not in json.dumps(out)


def test_ids_de_protocole_intacts():
    sub = make_sub(to_surrogate=lambda s: "MODIFIÉ")
    body = {"messages": [{"role": "assistant", "content": [
        {"type": "tool_use", "id": "toolu_01ABC", "name": "bash", "input": {"cmd": "ls"}}]}]}
    out = walk_request(body, sub)
    blk = out["messages"][0]["content"][0]
    assert blk["id"] == "toolu_01ABC" and blk["type"] == "tool_use" and blk["name"] == "bash"
    # Le NOM d'un argument est une donnée, pas un contrat : le modèle écrit
    # `{"db-01.acme.internal": …}` et le nom d'hôte sortait verbatim. Il passe
    # donc par le détecteur comme le reste — qui ne signale ni `cmd` ni `path`,
    # et ne les touche donc pas en pratique. Ici le substituteur modifie TOUT.
    assert list(blk["input"].values()) == ["MODIFIÉ"]


# --------------------------------------------------------------------------- #
# Round 3 — la restauration doit couvrir TOUT le flux, pas seulement les
# `text_delta` et les `tool_use` accumulés. Un passthrough par défaut est
# fail-open pour la restauration : l'opérateur voit le substitut à la place de
# sa propre valeur, sans aucun signal.
# --------------------------------------------------------------------------- #


def test_le_bloc_de_demarrage_est_restaure():
    """`content_block_start` n'est pas vide : il porte déjà des valeurs."""
    rw = SSERewriter(make_sub())
    out = list(rw.feed({
        "type": "content_block_start", "index": 0,
        "content_block": {
            "type": "mcp_tool_use", "id": "mcp_1", "name": "search",
            "server_name": "billing-api",
            "input": {"host": "cluster-01-prod.northwind.internal"},
        },
    }))
    bloc = out[0]["content_block"]
    assert bloc["input"]["host"] == "db-master-01-prod.acme.internal"
    # les identifiants de protocole restent intacts
    assert bloc["id"] == "mcp_1" and bloc["type"] == "mcp_tool_use"
    # `server_name` désigne l'entrée `mcp_servers[].name`, qui reste VERBATIM
    # (clé de routage, fuite assumée). Le substituer à l'aller cassait la
    # correspondance ; il n'y a donc rien à restaurer au retour.
    assert bloc["server_name"] == "billing-api"


def test_un_delta_non_enumere_est_restaure():
    """`citations_delta` porte `cited_text` — il existe déjà côté API."""
    rw = SSERewriter(make_sub())
    out = list(rw.feed({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "citations_delta",
                  "citation": {"type": "char_location",
                               "cited_text": "voir cluster-01-prod.northwind.internal",
                               "document_index": 0}},
    }))
    cite = out[0]["delta"]["citation"]
    assert cite["cited_text"] == "voir db-master-01-prod.acme.internal"
    assert out[0]["delta"]["type"] == "citations_delta"


def test_les_deltas_signes_restent_opaques():
    """Le pendant : toucher un thinking_delta invaliderait sa signature (D3)."""
    rw = SSERewriter(make_sub())
    for dtype, champ, valeur in (
            ("thinking_delta", "thinking", "cluster-01-prod.northwind.internal"),
            ("signature_delta", "signature", "cluster-01-prod.northwind.internal")):
        event = {"type": "content_block_delta", "index": 0,
                 "delta": {"type": dtype, champ: valeur}}
        assert list(rw.feed(event)) == [event], f"{dtype} modifié"


def test_un_delta_orphelin_est_traite_et_non_relaye_brut():
    """Sans `content_block_start`, le delta partait brut avec ses substituts."""
    rw = SSERewriter(make_sub())
    out = list(rw.feed({
        "type": "content_block_delta", "index": 7,
        "delta": {"type": "text_delta", "text": "hôte cluster-01-prod.northwind.internal fin"},
    }))
    out += list(rw.feed({"type": "content_block_stop", "index": 7}))
    assert "cluster-01-prod.northwind.internal" not in json.dumps(out)
    assert "db-master-01-prod.acme.internal" in json.dumps(out)


def test_un_json_partiel_orphelin_n_est_jamais_resolu_en_vol():
    """D2 tient aussi pour un `input_json_delta` sans bloc de démarrage."""
    rw = SSERewriter(make_sub())
    emis = list(rw.feed({
        "type": "content_block_delta", "index": 3,
        "delta": {"type": "input_json_delta", "partial_json": '{"h": "cluster-01'},
    }))
    assert emis == [], "un JSON partiel a été émis avant le stop"


@pytest.mark.parametrize("sep", ["\r\n\r\n", "\r\r", "\n\n"])
def test_les_trois_separateurs_sse_sont_reconnus(sep):
    """Un flux en CRLF ne rendait AUCUN bloc : tampon sans fin, zéro erreur."""
    from anonproxy.sse import iter_blocks
    ligne = sep[:len(sep) // 2]  # même convention de fin de ligne que le bloc
    flux = "event: ping" + ligne + "data: {}" + sep
    blocks, reste = iter_blocks(flux, "")
    assert len(blocks) == 1, f"séparateur {sep!r} non reconnu"
    assert reste == ""


@pytest.mark.parametrize("sep", ["\r\n\r\n", "\r\r", "\n\n", "\n\r\n", "\r\n\r", "\n\r"])
def test_toutes_les_fins_de_ligne_sse_sont_reconnues(sep):
    """Un séparateur = DEUX fins de ligne, chacune CR, LF ou CRLF, mélangeables."""
    from anonproxy.sse import iter_blocks
    blocks, reste = iter_blocks(f"data: a{sep}data: b{sep}", "")
    assert len(blocks) == 2, f"séparateur {sep!r} non reconnu"
    assert reste == ""


def test_un_crlf_simple_n_est_pas_un_separateur():
    """Sinon la répétition rétro-traque et chaque LIGNE devient un bloc."""
    from anonproxy.sse import iter_blocks
    blocks, reste = iter_blocks("event: ping\r\ndata: {}\r\n\r\n", "")
    assert len(blocks) == 1, f"un \\r\\n simple a été pris pour un séparateur : {blocks}"
    assert blocks[0] == "event: ping\r\ndata: {}"


def test_un_separateur_coupe_entre_deux_chunks_n_est_pas_invente():
    """`data: a\\r` + `\\nb` : le CRLF est une seule fin de ligne, pas deux."""
    from anonproxy.sse import iter_blocks
    blocks, reste = iter_blocks("data: a\r", "")
    assert blocks == []
    blocks, reste = iter_blocks("\nb", reste)
    assert blocks == [], f"bloc inventé sur une coupure de chunk : {blocks}"
    assert reste == "data: a\r\nb"
