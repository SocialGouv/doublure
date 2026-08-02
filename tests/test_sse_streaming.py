"""Phase 3 TEST-FIRST — streaming SSE et traversée du walker (D2, D3, D5).

Ces trois-là « ne se déboguent pas après coup » : substitut coupé entre deux
chunks, arguments d'outils jamais résolus en flux, blocs thinking opaques.

Le walker (`anthropic_walker.py`) est fourni : ces tests le mettent à
l'épreuve tel quel, ainsi que son câblage dans le proxy.
Données 100 % synthétiques.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from anthropic_walker import (  # noqa: E402
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
    assert blk["input"]["cmd"] == "MODIFIÉ"
