"""L'API d'arbitrage : une surface de CONTRÔLE, jamais un point d'application.

Le test qui compte n'est pas « les routes répondent » mais **désinstaller
l'interface n'ouvre rien**. Tout le reste en découle.
"""
from __future__ import annotations

import json
import os
import socket
import stat

import pytest
from fastapi.testclient import TestClient

from anonproxy.policy import Decision, Policy
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "e5" * 32
SCOPE = "project:api"
HOTE = "db-master-01-prod.acmecorp.internal"


@pytest.fixture
def bac(tmp_path, monkeypatch):
    """Un état complet, isolé, avec une valeur déjà anonymisée."""
    cle = tmp_path / "cle"
    cle.write_text(MASTER, encoding="utf-8")
    monkeypatch.setenv("ANONPROXY_MASTER_KEY_FILE", str(cle))
    monkeypatch.setenv("ANONPROXY_VAULT", str(tmp_path / "coffre.db"))
    monkeypatch.setenv("ANONPROXY_POLICY_DIR", str(tmp_path / "politique"))
    monkeypatch.setenv("ANONPROXY_SCOPE", SCOPE)
    monkeypatch.delenv("ANONPROXY_SESSION", raising=False)
    for nom in ("ANONPROXY_MODE", "ANONPROXY_ANNONCE", "ANONPROXY_ARBITRAGE"):
        monkeypatch.delenv(nom, raising=False)

    politique = Policy(racine=tmp_path / "politique", master_key=MASTER,
                       scope_key=SCOPE)
    moteur = SurrogateEngine(vault=Vault(tmp_path / "coffre.db", master_key=MASTER),
                            master_key=MASTER, scope_key=SCOPE, policy=politique)
    substitut = moteur.substitute_value("HOSTNAME", HOTE)
    return {"tmp": tmp_path, "politique": politique, "moteur": moteur,
            "substitut": substitut}


@pytest.fixture
def client(bac):
    from anonproxy import policy_api

    policy_api.app.state.anon = None      # état recalculé depuis l'env du bac
    with TestClient(policy_api.app) as c:
        yield c


# --------------------------------------------------------------------------- #
# L'invariant : l'interface ne protège rien, donc son absence n'ouvre rien
# --------------------------------------------------------------------------- #
def test_sans_l_api_la_protection_est_identique(bac):
    """Aucune route n'a été appelée : la valeur est anonymisée pareil."""
    autre = "web-42-prod.acmecorp.internal"
    assert bac["moteur"].substitute_value("HOSTNAME", autre) != autre


def test_l_api_ne_peut_pas_reveler_un_secret(client):
    """D4 passe AVANT l'opérateur : l'API n'est pas une dérogation."""
    r = client.post("/arbitrer", json={"granularite": "classe", "cle": "secret",
                                       "decision": "reveler", "portee": "global"})
    assert r.status_code == 409
    assert "jamais révélable" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# Ce que l'interface a besoin de voir
# --------------------------------------------------------------------------- #
def test_les_questions_portent_la_valeur_reelle(client, bac):
    """C'est la raison d'être de l'API — et pourquoi elle n'est pas sur un port."""
    questions = client.get("/questions").json()["questions"]
    assert len(questions) == 1
    q = questions[0]
    assert q["valeur"] == HOTE.lower()
    assert q["substitut"] == bac["substitut"]
    assert q["type"] == "HOSTNAME"


def test_sante_donne_le_mode_et_les_reglages(client):
    corps = client.get("/sante").json()
    assert corps["statut"] == "ok"
    assert corps["reglages"]["mode"] == "auto"
    assert set(corps["modes"]) == {"auto", "consciencieux", "ferme"}
    assert corps["questions"] == 1


# --------------------------------------------------------------------------- #
# Arbitrer par l'API produit exactement le même effet que par la CLI
# --------------------------------------------------------------------------- #
def test_arbitrer_par_l_api_change_le_moteur(client, bac):
    r = client.post("/arbitrer", json={
        "granularite": "type", "cle": "HOSTNAME", "decision": "reveler"})
    assert r.status_code == 200
    assert "SORT désormais en clair" in r.json()["avertissement"]
    autre = "web-42-prod.acmecorp.internal"
    assert bac["moteur"].substitute_value("HOSTNAME", autre) == autre


def test_arbitrer_ne_laisse_aucune_valeur_reelle_dans_les_fichiers(client, bac):
    empreinte = bac["politique"].empreinte("HOSTNAME", HOTE.lower())
    client.post("/arbitrer", json={"granularite": "valeur", "cle": empreinte,
                                   "decision": "reveler"})
    ecrits = "\n".join(p.read_text(encoding="utf-8")
                       for p in (bac["tmp"] / "politique").glob("*.json"))
    assert "acmecorp" not in ecrits and HOTE not in ecrits


def test_une_question_tranchee_disparait(client, bac):
    client.post("/arbitrer", json={"granularite": "type", "cle": "HOSTNAME",
                                   "decision": "anonymiser"})
    assert client.get("/questions").json()["questions"] == []


def test_regler_le_mode_par_l_api(client):
    r = client.post("/reglages", json={"nom": "mode", "valeur": "consciencieux"})
    assert r.status_code == 200
    assert r.json()["reglages"]["arbitrage"] == "bloquant"


@pytest.mark.parametrize("charge,attendu", [
    ({"granularite": "type", "cle": "HOSTNAME", "decision": "peut-etre"}, 422),
    ({"granularite": "sous-type", "cle": "x", "decision": "reveler"}, 409),
    ({"granularite": "type", "cle": "x", "decision": "reveler",
      "portee": "tenant"}, 409),
])
def test_une_demande_invalide_est_refusee_pas_ignoree(client, charge, attendu):
    assert client.post("/arbitrer", json=charge).status_code == attendu


def test_un_reglage_inconnu_est_refuse(client):
    assert client.post("/reglages", json={"nom": "vitesse",
                                          "valeur": "vite"}).status_code == 422
    assert client.post("/reglages", json={"nom": "mode",
                                          "valeur": "rapide"}).status_code == 422


# --------------------------------------------------------------------------- #
# Le canal — c'est lui qui porte la sécurité, pas l'API
# --------------------------------------------------------------------------- #
def test_le_hook_refuse_la_socket_et_pas_le_loopback():
    """Le choix de la socket vient de LÀ, il faut donc le figer.

    Un port local aurait été joignable par l'agent, et cette API affiche les
    valeurs réelles : ce serait rouvrir la mitigation du gap §3.5.
    """
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent / "hooks"))
    import pretooluse_guard as g

    assert g.check_bash("curl -s --unix-socket /tmp/x.sock http://x/questions")
    assert not g.check_bash("curl -s http://127.0.0.1:8090/healthz")


def test_la_socket_est_creee_en_0600(tmp_path):
    """uvicorn crée la socket en 0666 : tout utilisateur local pourrait lire
    les valeurs réelles. Le lanceur la referme — on fige l'exigence."""
    chemin = tmp_path / "essai.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(chemin))
    try:
        os.chmod(chemin, 0o600)
        mode = stat.S_IMODE(os.stat(chemin).st_mode)
        assert mode == 0o600, oct(mode)
    finally:
        srv.close()


def test_le_lanceur_ne_duplique_pas_les_chemins_d_etat():
    """Deux jeux de valeurs par défaut auraient divergé : le shell demande à
    Python, il ne réécrit pas les chemins."""
    from pathlib import Path

    script = (Path(__file__).parent.parent / "scripts" / "run-policy-api.sh"
              ).read_text(encoding="utf-8")
    assert "chemin_socket" in script
    assert "vault" not in script.lower()
