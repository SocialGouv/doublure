"""Phase 3 — le proxy de bout en bout, contre un FAUX amont Anthropic.

Vérifie les propriétés qui comptent, sans réseau ni clé d'API :
  - aucune valeur réelle dans le corps sortant (les 4 surfaces) ;
  - restauration correcte au retour (JSON et SSE) ;
  - déterminisme octet pour octet (cache de prompt) ;
  - count_tokens substitué comme /v1/messages ;
  - fail-closed si le détecteur tombe ;
  - passthrough intact pour les chemins non modélisés.

Données 100 % synthétiques.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from anonproxy.detect import DetectionUnavailable  # noqa: E402
from anonproxy.proxy import app as proxy_app  # noqa: E402

# --- valeurs synthétiques « sensibles » utilisées dans les requêtes --------- #
REAL_HOST = "db-master-01-prod.acmecorp.internal"
REAL_IP = "10.1.2.3"
REAL_MAIL = "alice.dupont@acmecorp.example"
REAL_REPO = "https://github.com/acmecorp/payments-api"
REAL_TOKEN = "ghp_syntheticDemoToken1234567890abcdef"
REAL_VALUES = [REAL_HOST, REAL_IP, REAL_MAIL, REAL_REPO, REAL_TOKEN, "acmecorp"]


class FakeDetector:
    """Détecteur déterministe : regex sur les valeurs synthétiques ci-dessus.

    Remplace le service AnonShield (processus séparé) dans les tests, pour
    qu'ils tournent sans GPU ni modèle.
    """

    PATTERNS = [
        ("AUTH_TOKEN", re.compile(r"ghp_[A-Za-z0-9]+")),
        ("URL", re.compile(r"https://github\.com/[\w.-]+/[\w.-]+")),
        ("EMAIL_ADDRESS", re.compile(r"[\w.+-]+@[\w.-]+\.\w+")),
        ("HOSTNAME", re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.internal\b")),
        ("IP_ADDRESS", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    ]

    def __init__(self):
        self.calls = 0
        self.fail = False

    def detect(self, text, *, strategy=None):
        if self.fail:
            raise DetectionUnavailable("détecteur simulé hors service")
        self.calls += 1
        out = []
        for etype, pat in self.PATTERNS:
            for m in pat.finditer(text):
                out.append({"type": etype, "value": m.group(0), "start": m.start(),
                            "end": m.end(), "score": 0.9})
        # GARDE-FOU ANTI-COMPLAISANCE : si la fixture évolue vers une valeur que
        # ces motifs n'attrapent pas, les tests « aucune fuite » passeraient
        # trivialement — rien à substituer, donc rien à faire fuir. On échoue
        # bruyamment plutôt que de rassurer à tort.
        couverts = {e["value"] for e in out}
        for reel in REAL_VALUES:
            if reel in text and not any(reel in c or c in reel for c in couverts):
                raise AssertionError(
                    f"FakeDetector ne couvre pas {reel!r} : le test ne prouverait rien. "
                    "Ajouter un motif, ou vérifier ce cas via tests/phase3_e2e.sh."
                )
        return out

    def health(self):
        if self.fail:
            raise DetectionUnavailable("détecteur simulé hors service")
        return {"status": "ok", "model": "fake", "warm": True}

    def close(self):
        pass


class FakeUpstream:
    """Faux api.anthropic.com : capture les corps sortants, rejoue des réponses."""

    def __init__(self):
        self.requests: list[dict] = []
        self.mode = "json"

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        self.requests.append({"path": request.url.path, "body": body,
                              "headers": dict(request.headers)})

        if request.url.path.endswith("/count_tokens"):
            return httpx.Response(200, json={"input_tokens": 1234})

        if request.url.path == "/v1/messages":
            # renvoie le contenu SUBSTITUÉ reçu, pour valider la restauration
            echo = json.dumps(body.get("messages", []))
            found = sorted(set(re.findall(r"[\w.@-]{6,}", echo)))
            if self.mode == "sse":
                return httpx.Response(200, headers={"content-type": "text/event-stream"},
                                      content=self._sse(found))
            return httpx.Response(200, json={
                "id": "msg_01", "type": "message", "role": "assistant",
                "model": "claude-fable-5",
                "content": [
                    {"type": "thinking", "thinking": f"opaque {found[0] if found else ''}",
                     "signature": "sig-abc"},
                    {"type": "text", "text": "vu : " + " ".join(found)},
                    {"type": "tool_use", "id": "toolu_9", "name": "bash",
                     "input": {"command": "ssh " + (found[0] if found else "rien")}},
                ],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 20},
            })

        return httpx.Response(200, json={"passthrough": True, "path": request.url.path})

    @staticmethod
    def _sse(found: list[str]) -> bytes:
        text = "vu : " + " ".join(found)
        out = [
            {"type": "message_start", "message": {"id": "msg_1", "type": "message",
                                                  "role": "assistant", "content": [],
                                                  "model": "claude-fable-5"}},
            {"type": "content_block_start", "index": 0,
             "content_block": {"type": "text", "text": ""}},
        ]
        # texte coupé en tranches de 7 caractères : les substituts sont scindés
        out += [{"type": "content_block_delta", "index": 0,
                 "delta": {"type": "text_delta", "text": text[i:i + 7]}}
                for i in range(0, len(text), 7)]
        out += [
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {}},
            {"type": "message_stop"},
        ]
        blob = b""
        for ev in out:
            blob += f"event: {ev['type']}\ndata: {json.dumps(ev)}\n\n".encode()
        return blob


@pytest.fixture
def proxy(tmp_path, monkeypatch):
    monkeypatch.setenv("ANONPROXY_SCOPE", "project:test")
    monkeypatch.setenv("ANONPROXY_VAULT", str(tmp_path / "vault.db"))
    key = tmp_path / "key"
    key.write_text("f" * 64)
    monkeypatch.setenv("ANONPROXY_MASTER_KEY_FILE", str(key))

    upstream = FakeUpstream()
    detector = FakeDetector()

    real_state_init = proxy_app.ProxyState.__init__

    def patched_init(self, settings):
        real_state_init(self, settings)
        self.detector.close()
        self.detector = detector
        self.pseudonymizer.detector = detector
        self.client = httpx.AsyncClient(
            transport=httpx.MockTransport(upstream.handler),
            base_url="https://api.anthropic.com",
        )

    monkeypatch.setattr(proxy_app.ProxyState, "__init__", patched_init)
    with TestClient(proxy_app.app) as client:
        yield client, upstream, detector


def sample_body(stream: bool = False) -> dict:
    return {
        "model": "claude-fable-5",
        "max_tokens": 100,
        "stream": stream,
        "system": [{"type": "text", "text": f"Cluster {REAL_HOST} en production",
                    "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {"role": "user", "content": f"connecte-toi à {REAL_IP} et préviens {REAL_MAIL}"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "bash",
                 "input": {"command": f"git clone {REAL_REPO}"}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1",
                 "content": f"cloné depuis {REAL_REPO} avec le jeton {REAL_TOKEN}"}]},
        ],
        "tools": [{
            "name": "query_db",
            "description": f"interroge la base sur {REAL_HOST}",
            "input_schema": {"type": "object",
                             "properties": {"host": {"type": "string",
                                                     "description": f"défaut {REAL_IP}"}},
                             "required": ["host"]},
        }],
        "metadata": {"user_id": REAL_MAIL},
    }


# --------------------------------------------------------------------------- #


def test_aucune_valeur_reelle_ne_sort(proxy):
    client, upstream, _ = proxy
    r = client.post("/v1/messages", json=sample_body())
    assert r.status_code == 200
    sent = json.dumps(upstream.requests[-1]["body"], ensure_ascii=False)
    for real in REAL_VALUES:
        assert real not in sent, f"FUITE : {real!r} est parti à l'amont"


def test_structure_preservee(proxy):
    client, upstream, _ = proxy
    client.post("/v1/messages", json=sample_body())
    body = upstream.requests[-1]["body"]
    assert body["model"] == "claude-fable-5"
    assert body["max_tokens"] == 100
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert body["tools"][0]["name"] == "query_db"
    assert body["tools"][0]["input_schema"]["required"] == ["host"]
    assert body["messages"][1]["content"][0]["id"] == "t1"


def test_restauration_json(proxy):
    client, _, _ = proxy
    r = client.post("/v1/messages", json=sample_body())
    content = r.json()["content"]
    text = next(b["text"] for b in content if b["type"] == "text")
    cmd = next(b["input"]["command"] for b in content if b["type"] == "tool_use")
    # le faux amont a renvoyé les substituts : le proxy doit rendre le réel.
    # Pas de branche « ou rien » : si le pipeline vidait le contenu, le faux
    # amont renverrait « rien » et le test passerait pour la mauvaise raison.
    assert REAL_HOST in text or REAL_IP in text or REAL_MAIL in text
    assert any(v in cmd for v in REAL_VALUES), f"aucune valeur réelle restaurée : {cmd!r}"


def test_thinking_reste_opaque(proxy):
    client, _, _ = proxy
    r = client.post("/v1/messages", json=sample_body())
    thinking = next(b for b in r.json()["content"] if b["type"] == "thinking")
    assert thinking["signature"] == "sig-abc"
    assert thinking["thinking"].startswith("opaque ")


def test_secret_jamais_restaure(proxy):
    """D4 : le jeton substitué ne doit JAMAIS revenir en clair."""
    client, upstream, _ = proxy
    r = client.post("/v1/messages", json=sample_body())
    assert REAL_TOKEN not in json.dumps(r.json())


def test_determinisme_octet_pour_octet(proxy):
    client, upstream, _ = proxy
    client.post("/v1/messages", json=sample_body())
    first = json.dumps(upstream.requests[-1]["body"], sort_keys=True)
    client.post("/v1/messages", json=sample_body())
    second = json.dumps(upstream.requests[-1]["body"], sort_keys=True)
    assert first == second, "corps sortant instable → cache de prompt perdu"


def test_cache_evite_les_appels_repetes(proxy):
    client, _, detector = proxy
    client.post("/v1/messages", json=sample_body())
    after_first = detector.calls
    client.post("/v1/messages", json=sample_body())
    assert detector.calls == after_first, "le cache ne fonctionne pas"


def test_streaming_restaure_a_travers_les_coupes(proxy):
    client, upstream, _ = proxy
    upstream.mode = "sse"
    with client.stream("POST", "/v1/messages", json=sample_body(stream=True)) as r:
        raw = b"".join(r.iter_bytes()).decode()
    texts = [json.loads(line[5:])["delta"]["text"]
             for line in raw.splitlines()
             if line.startswith("data:") and '"text_delta"' in line]
    joined = "".join(texts)
    sent = json.dumps(upstream.requests[-1]["body"])

    # Aucun substitut RÉVERSIBLE ne doit subsister côté opérateur — tous types
    # confondus, pas seulement les hôtes `.internal`. On dérive la liste des
    # substituts réellement émis en comparant au corps d'origine.
    origine = json.dumps(sample_body(stream=True))
    substituts = {tok for tok in re.findall(r"[\w.@:/-]{6,}", sent)
                  if tok not in origine and not tok.startswith("claude-")}
    # …à l'exception des secrets, qui ne sont JAMAIS restaurés (D4) : leur
    # substitut reste tel quel dans la vue de l'opérateur, par construction.
    reversibles = {s for s in substituts if not s.startswith("ghp_")}
    residuels = sorted(s for s in reversibles if s in joined)
    assert not residuels, f"substituts non restaurés dans le flux : {residuels[:5]}"
    assert REAL_TOKEN not in joined, "un secret a été restauré dans le flux (D4)"

    # …et toutes les valeurs réelles citées par l'amont sont revenues
    assert REAL_HOST in joined or REAL_IP in joined


def test_count_tokens_substitue(proxy):
    client, upstream, _ = proxy
    r = client.post("/v1/messages/count_tokens", json=sample_body())
    assert r.status_code == 200 and r.json() == {"input_tokens": 1234}
    sent = json.dumps(upstream.requests[-1]["body"], ensure_ascii=False)
    for real in REAL_VALUES:
        assert real not in sent, f"FUITE count_tokens : {real!r}"


def test_fail_closed_si_detecteur_hs(proxy):
    client, upstream, detector = proxy
    before = len(upstream.requests)
    detector.fail = True
    r = client.post("/v1/messages", json=sample_body())
    assert r.status_code == 503
    assert r.json()["error"]["type"] == "api_error"
    assert len(upstream.requests) == before, "requête transmise malgré l'échec de détection !"


def test_passthrough_autres_chemins(proxy):
    client, upstream, _ = proxy
    r = client.post("/api/event_logging/telemetry", json={"event": "x"})
    assert r.status_code == 200 and r.json()["passthrough"] is True


def test_healthz(proxy):
    client, _, _ = proxy
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["scope"] == "project:test"
