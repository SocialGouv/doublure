"""Phase 2 — comportement fail-closed (D4, D5, erreurs explicites).
Ces tests sont écrits AVANT l'implémentation (règle test-first).
Valeurs synthétiques uniquement."""
from __future__ import annotations

import pytest

from anonproxy.surrogates.engine import SurrogateEngine, SurrogateCollisionError
from anonproxy.vault import Vault, VaultUnavailableError

MASTER = "c5" * 32
SCOPE = "project:demo"


def make_engine(tmp_path):
    return SurrogateEngine(vault=Vault(tmp_path / "v.db", master_key=MASTER), master_key=MASTER, scope_key=SCOPE)


def test_secret_jamais_reversible(tmp_path):
    eng = make_engine(tmp_path)
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vLXN5bnRoIn0.ZmF1c3Nlc2lnbmF0dXJl"
    fake = eng.substitute_value("JWT", jwt)
    assert fake != jwt and fake.count(".") == 2
    # jamais dans la vue de restauration (D4 : un secret n'est pas restauré)
    assert fake not in eng.surrogates_view()
    # et le réel n'est stocké nulle part dans le coffre
    assert not eng.vault.real_exists(SCOPE, jwt)


def test_secret_deterministe_sans_stockage(tmp_path):
    eng = make_engine(tmp_path)
    tok = "ghp_synthDemoToken1234567890abcdefXYZ"
    f1 = eng.substitute_value("AUTH_TOKEN", tok)
    f2 = eng.substitute_value("AUTH_TOKEN", tok)
    assert f1 == f2, "substitut de secret non déterministe (cache de prompt cassé)"
    assert f1.startswith("ghp_"), "préfixe structurel perdu (plausibilité D1)"


def test_pas_de_sentinelles(tmp_path):
    eng = make_engine(tmp_path)
    for t, v in [("HOSTNAME", "db-01.acme.internal"), ("IP_ADDRESS", "10.1.2.3"),
                 ("JWT", "eyJhbGciOiJIUzI1NiJ9.eyJhIjoiYiJ9.c2ln")]:
        s = eng.substitute_value(t, v)
        for bad in ("[", "]", "<", ">", "HOST_", "IP_", "pseudo-", ".invalid"):
            assert bad not in s, f"sentinelle détectée (D1) : {v} → {s}"


def test_collision_epuisee_erreur_explicite(tmp_path, monkeypatch):
    eng = make_engine(tmp_path)
    # force le générateur à produire toujours le même candidat
    monkeypatch.setattr(
        "anonproxy.surrogates.engine.SurrogateEngine._candidate",
        lambda self, etype, value, attempt, canon=None: "collision-fixe",
    )
    eng.substitute_value("K8S_NAMESPACE", "ns-alpha")
    with pytest.raises(SurrogateCollisionError):
        eng.substitute_value("K8S_NAMESPACE", "ns-beta")


def test_coffre_indisponible_erreur_explicite(tmp_path):
    p = tmp_path / "inexistant" / "sous" / "v.db"  # parent absent, non créé
    with pytest.raises(VaultUnavailableError):
        Vault(p, master_key=MASTER, create_parents=False)


def test_substitut_inconnu_jamais_devine():
    """Sens entrant : un substitut absent de la table reste en place (D5)."""
    import sys
    sys.path.insert(0, "/home/jo/lab/ai/anonshield+claude-code")
    from anthropic_walker import Substituter

    sub = Substituter(to_surrogate=lambda t: t, surrogates={"vrai-connu": "réel"})
    out, unresolved = sub.to_real("cmd sur hote-invente-par-le-modele et vrai-connu")
    assert "hote-invente-par-le-modele" in out, "substitut inconnu modifié !"
    assert "réel" in out
    assert unresolved == []  # inconnu ≠ matché : il ne PEUT pas l'être (pattern = clés connues)


def test_vue_surrogates_ne_contient_que_du_reversible(tmp_path):
    eng = make_engine(tmp_path)
    host = eng.substitute_value("HOSTNAME", "web-01.acme.internal")
    secret = eng.substitute_value("PASSWORD_CONTEXT", "password: sUp3rSynth!")
    view = eng.surrogates_view()

    assert view[host] == "web-01.acme.internal"       # l'hôte est réversible
    assert secret not in view                          # le secret ne l'est JAMAIS
    assert "password: sUp3rSynth!" not in view.values()
    # les attributs partagés (zone) sont exclus : les exposer permettrait de
    # résoudre partiellement un substitut inventé par le modèle (D5)
    assert "acme.internal" not in view.values()
    assert all(not k.startswith("school.") for k in view)
