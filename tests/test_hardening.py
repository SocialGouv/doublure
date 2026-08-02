"""Phase 6 — durcissement : comportement défini et TESTÉ quand le coffre
est indisponible, et absence de données sensibles dans l'observabilité.

Le plan exige un comportement fail-closed « défini et testé » : c'est ici.
Données synthétiques uniquement.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from anonproxy.pipeline import Pseudonymizer  # noqa: E402
from anonproxy.surrogates.engine import SurrogateEngine  # noqa: E402
from anonproxy.vault import SurrogateConflict, Vault, VaultUnavailableError  # noqa: E402

MASTER = "f8" * 32
SCOPE = "project:hard"


def engine(path: Path) -> SurrogateEngine:
    return SurrogateEngine(vault=Vault(path), master_key=MASTER, scope_key=SCOPE)


# --------------------------------------------------------------------------- #
# Coffre indisponible → fail-closed, jamais de mode dégradé
# --------------------------------------------------------------------------- #


def test_repertoire_inexistant_refuse(tmp_path):
    with pytest.raises(VaultUnavailableError) as exc:
        Vault(tmp_path / "absent" / "vault.db", create_parents=False)
    assert "coffre indisponible" in str(exc.value)


def test_coffre_illisible_refuse(tmp_path):
    p = tmp_path / "vault.db"
    Vault(p).close()
    p.chmod(0)
    try:
        with pytest.raises(VaultUnavailableError):
            Vault(p)
    finally:
        p.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_coffre_corrompu_refuse(tmp_path):
    p = tmp_path / "vault.db"
    p.write_bytes(b"ceci n'est pas une base SQLite" * 50)
    with pytest.raises(VaultUnavailableError):
        Vault(p)


def test_ecriture_impossible_propage(tmp_path):
    """Coffre en lecture seule : l'erreur remonte, aucune substitution
    silencieusement non persistée (qui serait irréversible au retour)."""
    p = tmp_path / "vault.db"
    eng = engine(p)
    eng.substitute_value("HOSTNAME", "web-01.acme.internal")
    eng.vault.close()
    p.chmod(stat.S_IRUSR)
    try:
        eng2 = engine(p)
        with pytest.raises((sqlite3.Error, VaultUnavailableError, OSError)):
            eng2.substitute_value("HOSTNAME", "web-02.acme.internal")
    finally:
        p.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_injectivite_garantie_par_la_base(tmp_path):
    """Défense en profondeur : même en forçant, la base refuse un doublon."""
    v = Vault(tmp_path / "vault.db")
    v.bind(SCOPE, "HOSTNAME", "a.acme.internal", "aa.northwind.internal")
    with pytest.raises(SurrogateConflict):
        v.bind(SCOPE, "HOSTNAME", "b.acme.internal", "aa.northwind.internal")


def test_meme_reel_deux_fois_renvoie_le_meme_substitut(tmp_path):
    v = Vault(tmp_path / "vault.db")
    first = v.bind(SCOPE, "HOSTNAME", "a.acme.internal", "aa.northwind.internal")
    second = v.bind(SCOPE, "HOSTNAME", "a.acme.internal", "bb.northwind.internal")
    assert first == second == "aa.northwind.internal"


# --------------------------------------------------------------------------- #
# Détecteur indisponible → la requête est refusée, rien ne part
# --------------------------------------------------------------------------- #


class DeadDetector:
    def detect(self, text, *, strategy=None):
        from anonproxy.detect import DetectionUnavailable
        raise DetectionUnavailable("service arrêté")


def test_detecteur_hs_propage_sans_texte_en_clair(tmp_path):
    from anonproxy.detect import DetectionUnavailable

    p = Pseudonymizer(DeadDetector(), engine(tmp_path / "v.db"))
    secret_text = "connexion à db-master-01.acme.internal"
    with pytest.raises(DetectionUnavailable) as exc:
        p.to_surrogate(secret_text)
    assert "db-master-01.acme.internal" not in str(exc.value), \
        "le message d'erreur ne doit pas contenir la donnée sensible"


# --------------------------------------------------------------------------- #
# Observabilité sans données sensibles
# --------------------------------------------------------------------------- #


def test_journaux_ne_contiennent_pas_de_valeurs_reelles(tmp_path, caplog, capsys):
    """Couvre les TROIS canaux : `logging`, stdout et stderr. `caplog` seul
    laisserait passer un `print` de débogage oublié."""
    eng = engine(tmp_path / "v.db")
    with caplog.at_level(logging.DEBUG):
        eng.substitute_value("HOSTNAME", "db-master-01-prod.acme.internal")
        eng.substitute_value("EMAIL_ADDRESS", "alice.dupont@acme.example")
        eng.substitute_value("AUTH_TOKEN", "ghp_synthDemo1234567890abcdefGHIJ")
        eng.substitute_value("IP_ADDRESS", "10.77.88.99")
    captured = capsys.readouterr()
    blob = "\n".join(r.getMessage() for r in caplog.records) + captured.out + captured.err
    for value in ("db-master-01-prod.acme.internal", "alice.dupont@acme.example",
                  "ghp_synthDemo1234567890abcdefGHIJ", "10.77.88.99"):
        assert value not in blob, f"{value!r} apparaît dans un journal"


def test_stats_du_pipeline_sont_des_compteurs(tmp_path):
    """Les statistiques exposées par /healthz ne doivent porter aucun texte."""
    class Fake:
        def detect(self, text, *, strategy=None):
            return []

    p = Pseudonymizer(Fake(), engine(tmp_path / "v.db"))
    p.to_surrogate("connexion à db-01.acme.internal depuis 10.1.2.3")
    assert all(isinstance(v, int) for v in p.stats.values())
    assert "acme" not in json.dumps(p.stats)


# --------------------------------------------------------------------------- #
# Suppression cryptographique (le socle de l'effacement)
# --------------------------------------------------------------------------- #


def test_portee_isolee_dans_la_base(tmp_path):
    """Isolation par portée : supprimer les lignes d'une portée n'affecte
    pas les autres — socle de la suppression ciblée (Phase 6 du plan)."""
    v = Vault(tmp_path / "v.db")
    a = SurrogateEngine(vault=v, master_key=MASTER, scope_key="project:a")
    b = SurrogateEngine(vault=v, master_key=MASTER, scope_key="project:b")
    a.substitute_value("HOSTNAME", "db.acme.internal")
    b.substitute_value("HOSTNAME", "db.acme.internal")
    # un hôte = une entrée d'hôte + une entrée de zone partagée, par portée
    assert v.count("project:a") == 2 and v.count("project:b") == 2
    avant_b = v.view("project:b")

    with v._conn:  # suppression ciblée d'une portée
        v._conn.execute("DELETE FROM mapping WHERE scope=?", ("project:a",))
    assert v.count("project:a") == 0
    assert v.view("project:b") == avant_b, "la portée voisine a été altérée"


def test_perte_de_cle_rend_la_derivation_differente(tmp_path):
    """La clé maître + la base = les deux moitiés du secret : sans la bonne
    clé, les substituts générés diffèrent (la base seule ne suffit pas)."""
    v_path = tmp_path / "v.db"
    e1 = SurrogateEngine(vault=Vault(v_path), master_key=MASTER, scope_key=SCOPE)
    s1 = e1._candidate("HOSTNAME", "db-01.acme.internal", 0)
    e2 = SurrogateEngine(vault=Vault(tmp_path / "autre.db"),
                         master_key="00" * 32, scope_key=SCOPE)
    s2 = e2._candidate("HOSTNAME", "db-01.acme.internal", 0)
    assert s1 != s2
