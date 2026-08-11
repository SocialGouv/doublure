"""The forward proxy, proven against a real client and a real TLS origin.

A unit test on the CONNECT parser would prove the parser. What has to be true
is that an ordinary HTTPS client, given `HTTPS_PROXY`, reaches an origin
through us — and does not reach one we refused. So the test starts both ends
and speaks the protocol.

The origin's certificate is signed by our own interception authority, which
means the test also exercises the chain the client will have to accept in
production.
"""
from __future__ import annotations

import http.server
import ssl
import threading
from pathlib import Path

import httpx
import pytest

from anonproxy.forward.ca import InterceptionCA
from anonproxy.forward.policy import ForwardPolicy
from anonproxy.forward.proxy import ForwardProxy


class _Origine(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — imposé par BaseHTTPRequestHandler
        corps = b'{"hote": "origine", "chemin": "%s"}' % self.path.encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def log_message(self, *_):
        pass  # le serveur de test n'a pas à bavarder sur stderr


@pytest.fixture(scope="module")
def ca(tmp_path_factory) -> InterceptionCA:
    autorite = InterceptionCA(tmp_path_factory.mktemp("etat"))
    autorite.ensure()
    return autorite


@pytest.fixture(scope="module")
def origine(ca, tmp_path_factory) -> int:
    """Un vrai serveur HTTPS sur 127.0.0.1, certifié par notre autorité."""
    cert_pem, cle_pem = ca.leaf_for("127.0.0.1")
    dossier = tmp_path_factory.mktemp("origine")
    cert, cle = dossier / "c.pem", dossier / "k.pem"
    cert.write_bytes(cert_pem)
    cle.write_bytes(cle_pem)

    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexte.load_cert_chain(certfile=str(cert), keyfile=str(cle))
    serveur = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origine)
    serveur.socket = contexte.wrap_socket(serveur.socket, server_side=True)
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    yield serveur.server_address[1]
    serveur.shutdown()


def _proxy(politique: ForwardPolicy, ca: InterceptionCA) -> ForwardProxy:
    proxy = ForwardProxy(politique, ca)
    proxy.start_in_thread()
    return proxy


def _client(proxy: ForwardProxy, ca: InterceptionCA) -> httpx.Client:
    return httpx.Client(proxy=f"http://127.0.0.1:{proxy.port}",
                        verify=str(ca.cert_path), timeout=10)


def test_a_tunnelled_destination_is_reached_through_the_proxy(ca, origine):
    """La preuve : un client HTTPS ordinaire, un proxy explicite, une origine
    réelle. Le certificat vu par le client est celui de l'ORIGINE — un tunnel
    ne se met pas au milieu."""
    proxy = _proxy(ForwardPolicy(inspect=[], tunnel=["127.0.0.1"]), ca)
    try:
        with _client(proxy, ca) as client:
            r = client.get(f"https://127.0.0.1:{origine}/salut")
        assert r.status_code == 200
        assert r.json()["chemin"] == "/salut"
    finally:
        proxy.stop()


def test_an_unlisted_destination_never_gets_a_connection(ca, origine):
    """FAIL-CLOSED : le refus intervient avant la moindre connexion sortante,
    et le client le voit — il ne reçoit pas un silence."""
    proxy = _proxy(ForwardPolicy(inspect=[], tunnel=["ailleurs.test"]), ca)
    try:
        with _client(proxy, ca) as client:
            with pytest.raises(httpx.ProxyError):
                client.get(f"https://127.0.0.1:{origine}/salut")
    finally:
        proxy.stop()


def test_an_inspected_destination_is_refused_while_interception_is_absent(ca, origine):
    """Relayer en clair une destination déclarée À INSPECTER serait un
    fail-open silencieux : l'opérateur a demandé qu'on lise, il n'aurait rien
    lu du tout et rien ne le lui aurait dit."""
    proxy = _proxy(ForwardPolicy(inspect=["127.0.0.1"], tunnel=[]), ca)
    try:
        with _client(proxy, ca) as client:
            with pytest.raises(httpx.ProxyError):
                client.get(f"https://127.0.0.1:{origine}/salut")
        assert any("interception" in d.reason for d in proxy.decisions)
    finally:
        proxy.stop()


def test_every_decision_is_traced(ca, origine):
    """Un résidu accepté doit être COMPTÉ. Un proxy qui refuse sans laisser de
    trace fait chercher la panne dans l'agent."""
    proxy = _proxy(ForwardPolicy(inspect=[], tunnel=["127.0.0.1"]), ca)
    try:
        with _client(proxy, ca) as client:
            client.get(f"https://127.0.0.1:{origine}/salut")
        assert [(d.destination, d.verdict.value) for d in proxy.decisions] == [
            (f"127.0.0.1:{origine}", "tunnel")]
    finally:
        proxy.stop()


def test_plain_http_to_a_third_party_is_refused(ca, origine):
    """Une requête en forme absolue (`GET http://hôte/…`) ne peut être ni
    tunnelée ni lue tant que l'interception n'existe pas : la refuser est la
    seule réponse qui ne mente pas."""
    proxy = _proxy(ForwardPolicy(inspect=[], tunnel=["127.0.0.1"]), ca)
    try:
        with httpx.Client(proxy=f"http://127.0.0.1:{proxy.port}",
                          timeout=10) as client:
            r = client.get("http://127.0.0.1/salut")
        assert r.status_code == 403
    finally:
        proxy.stop()


def test_the_authority_file_is_what_a_client_must_trust(ca):
    """Le lanceur pose ce chemin dans l'environnement du processus lancé —
    `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`. S'il n'existe pas, l'agent échoue
    sur une erreur de confiance illisible."""
    assert Path(ca.cert_path).is_file()
    assert b"BEGIN CERTIFICATE" in ca.cert_path.read_bytes()
