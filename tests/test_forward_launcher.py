"""The launcher — one entry point for any agent, and its two traps.

`ANTHROPIC_BASE_URL` names one API of one vendor. `HTTPS_PROXY` names none,
which is what makes a single launcher enough instead of one integration per
agent.

Both traps below cost a session to whoever forgets them, and neither shows up
as "the proxy is misconfigured": they show up as a trust error nobody connects
to the proxy.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

from anonproxy.forward.ca import InterceptionCA
from anonproxy.forward.launcher import build_env, run
from anonproxy.forward.policy import ForwardPolicy, Verdict


@pytest.fixture
def ca(tmp_path):
    autorite = InterceptionCA(tmp_path / "etat")
    autorite.ensure()
    return autorite


def test_the_bundle_keeps_the_system_roots(ca):
    """PIÈGE : pointer les variables sur notre seule autorité fait échouer tout
    accès TLS que le proxy ne fabrique pas. On AJOUTE, on ne remplace pas."""
    paquet = ca.bundle_path().read_bytes()
    assert paquet.count(b"BEGIN CERTIFICATE") > 1, \
        "le paquet ne contient que notre autorité : tout le reste casse"
    assert ca.cert_path.read_bytes() in paquet


def test_every_runtime_gets_the_variable_it_actually_reads(ca):
    """PIÈGE : Node ignore le magasin du système et ne lit QUE
    `NODE_EXTRA_CA_CERTS`. Python, curl et git ont chacun la leur."""
    env = build_env({}, ca, 8899)
    paquet = str(ca.bundle_path())
    for nom in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"):
        assert env[nom] == paquet, nom


def test_the_proxy_is_announced_in_both_cases(ca):
    """Les runtimes ne s'accordent pas sur la casse : Node lit `HTTPS_PROXY`,
    plusieurs bibliothèques Python lisent `https_proxy`."""
    env = build_env({}, ca, 8899)
    assert env["HTTPS_PROXY"] == env["https_proxy"] == "http://127.0.0.1:8899"


def test_the_local_detector_stays_direct(ca):
    """Faire transiter la boucle locale par le proxy ferait dépendre le
    détecteur de lui-même."""
    env = build_env({}, ca, 8899)
    assert "127.0.0.1" in env["NO_PROXY"] and "localhost" in env["NO_PROXY"]


def test_the_environment_of_the_caller_survives(ca):
    """L'agent a besoin de son PATH et de ses propres réglages : on complète,
    on ne repart pas de zéro."""
    env = build_env({"PATH": "/usr/bin", "ANTHROPIC_API_KEY": "gardé"}, ca, 1)
    assert env["PATH"] == "/usr/bin"
    assert env["ANTHROPIC_API_KEY"] == "gardé"


def test_the_command_runs_under_the_proxy_and_it_stops_after(ca, tmp_path):
    """Preuve : un processus enfant voit bien les variables, et le proxy ne
    survit pas à la commande — une interception qui reste debout après la
    session est une interception que plus personne n'a voulue."""
    code = run([sys.executable, "-c",
                "import os,sys; sys.exit(0 if os.environ['HTTPS_PROXY'] "
                "and os.environ['NODE_EXTRA_CA_CERTS'] else 1)"],
               state_dir=ca.state_dir)
    assert code == 0
    # Le port est refermé : une nouvelle instance peut le reprendre.
    with pytest.raises(RuntimeError):
        from anonproxy.forward.proxy import ForwardProxy
        ForwardProxy(ForwardPolicy([], []), ca).port


def test_the_exit_code_of_the_agent_is_the_exit_code(ca):
    """Un lanceur qui avale le code de retour rend la CI de l'agent aveugle."""
    assert run([sys.executable, "-c", "raise SystemExit(3)"],
               state_dir=ca.state_dir) == 3


# --------------------------------------------------------------------------- #
# Le fichier de destinations — chaque ligne OUVRE une sortie réseau
# --------------------------------------------------------------------------- #


def test_destinations_are_read_from_the_state_directory(tmp_path):
    fichier = tmp_path / "forward-destinations.txt"
    fichier.write_text("# commentaire\ninspect mcp.example.test\n"
                       "tunnel registry.example.test\n", encoding="utf-8")
    politique = ForwardPolicy.load(fichier)
    assert politique.verdict("mcp.example.test") is Verdict.INSPECT
    assert politique.verdict("registry.example.test") is Verdict.TUNNEL
    assert politique.verdict("ailleurs.test") is Verdict.REFUSE


def test_an_absent_file_opens_nothing(tmp_path):
    assert ForwardPolicy.load(tmp_path / "absent.txt").verdict("x.test") \
        is Verdict.REFUSE


def test_an_unknown_verb_is_an_error(tmp_path):
    """Le traiter comme un commentaire ferait d'une faute de frappe une
    destination absente en silence, donc refusée sans qu'on sache pourquoi."""
    fichier = tmp_path / "d.txt"
    fichier.write_text("inspecter mcp.example.test\n", encoding="utf-8")
    with pytest.raises(ValueError, match="inspecter"):
        ForwardPolicy.load(fichier)
