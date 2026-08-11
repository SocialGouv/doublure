"""Interception — the slice that turns a blocked channel into a readable one.

The decisive test design: the origin's certificate is signed by an authority
the client does **not** trust, and the client trusts only the interception
authority. If the request succeeds, the client necessarily validated OUR leaf —
interception is proven, not assumed.

Two properties matter as much as the reading itself:

- **the upstream certificate is verified.** Intercepting must not weaken what
  it replaces; a proxy that decrypts and then trusts anything has moved the
  attack surface rather than removed it;
- **what cannot be transformed is refused.** A streaming response we do not
  know how to rewrite must not be relayed untouched: the operator asked for the
  payload to be read, and silence would say it was.
"""
from __future__ import annotations

import http.server
import ssl
import threading

import httpx
import pytest

from anonproxy.forward.ca import InterceptionCA
from anonproxy.forward.policy import ForwardPolicy
from anonproxy.forward.proxy import ForwardProxy

VU: list[tuple[str, bytes]] = []


class _Origine(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):  # noqa: N802
        taille = int(self.headers.get("content-length", 0))
        recu = self.rfile.read(taille)
        VU.append(("recu", recu))
        corps = b'{"echo": true}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def do_GET(self):  # noqa: N802
        if self.path == "/flux":
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"data: un\n\n")
            return
        corps = b'{"chemin": "%s"}' % self.path.encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def log_message(self, *_):
        pass


@pytest.fixture(scope="module")
def interception(tmp_path_factory) -> InterceptionCA:
    """L'autorité que le CLIENT croit."""
    ca = InterceptionCA(tmp_path_factory.mktemp("etat-interception"))
    ca.ensure()
    return ca


@pytest.fixture(scope="module")
def autorite_origine(tmp_path_factory) -> InterceptionCA:
    """Une autorité DIFFÉRENTE, celle de l'origine. Le client ne la croit pas :
    c'est ce qui rend l'interception démontrable plutôt que supposée."""
    ca = InterceptionCA(tmp_path_factory.mktemp("etat-origine"))
    ca.ensure()
    return ca


@pytest.fixture(scope="module")
def origine(autorite_origine, tmp_path_factory) -> int:
    cert_pem, cle_pem = autorite_origine.leaf_for("127.0.0.1")
    dossier = tmp_path_factory.mktemp("origine-tls")
    pem = dossier / "origine.pem"
    pem.write_bytes(cert_pem + cle_pem)
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexte.load_cert_chain(certfile=str(pem))
    serveur = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origine)
    serveur.socket = contexte.wrap_socket(serveur.socket, server_side=True)
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    yield serveur.server_address[1]
    serveur.shutdown()


def _amont(autorite_origine) -> ssl.SSLContext:
    """Le contexte AMONT : il vérifie le vrai certificat de l'origine."""
    return ssl.create_default_context(cafile=str(autorite_origine.cert_path))


def _proxy(interception, autorite_origine, transform=None) -> ForwardProxy:
    proxy = ForwardProxy(ForwardPolicy(inspect=["127.0.0.1"], tunnel=[]),
                         interception,
                         upstream_context=_amont(autorite_origine),
                         transform=transform)
    proxy.start_in_thread()
    return proxy


def _client(proxy, interception) -> httpx.Client:
    contexte = ssl.create_default_context(cafile=str(interception.cert_path))
    return httpx.Client(proxy=f"http://127.0.0.1:{proxy.port}",
                        verify=contexte, timeout=10)


def test_the_client_validates_our_leaf_and_still_reaches_the_origin(
        interception, autorite_origine, origine):
    """Le client ne croit QUE l'autorité d'interception, et l'origine est
    signée par une autre : réussir prouve qu'il a validé notre feuille."""
    proxy = _proxy(interception, autorite_origine)
    try:
        with _client(proxy, interception) as client:
            r = client.get(f"https://127.0.0.1:{origine}/salut")
        assert r.status_code == 200
        assert r.json()["chemin"] == "/salut"
    finally:
        proxy.stop()


def test_the_body_is_handed_to_the_transform_in_both_directions(
        interception, autorite_origine, origine):
    vus: list[tuple[str, bytes]] = []

    class Espion:
        def outgoing(self, host, headers, body):
            vus.append(("sortant", body))
            return body

        def incoming(self, host, headers, body):
            vus.append(("entrant", body))
            return body

    proxy = _proxy(interception, autorite_origine, Espion())
    try:
        with _client(proxy, interception) as client:
            client.post(f"https://127.0.0.1:{origine}/rpc",
                        content=b'{"method": "outils/liste"}')
        assert ("sortant", b'{"method": "outils/liste"}') in vus
        assert ("entrant", b'{"echo": true}') in vus
    finally:
        proxy.stop()


def test_what_the_transform_returns_is_what_travels(
        interception, autorite_origine, origine):
    """Lire ne suffit pas : c'est la RÉÉCRITURE qui protège. L'origine doit
    recevoir le corps transformé, et le client la réponse transformée."""
    class Substitue:
        def outgoing(self, host, headers, body):
            return body.replace(b"db-01.acme.internal", b"hote-fictif.test")

        def incoming(self, host, headers, body):
            return body.replace(b"echo", b"restaure")

    VU.clear()
    proxy = _proxy(interception, autorite_origine, Substitue())
    try:
        with _client(proxy, interception) as client:
            r = client.post(f"https://127.0.0.1:{origine}/rpc",
                            content=b'{"hote": "db-01.acme.internal"}')
        assert ("recu", b'{"hote": "hote-fictif.test"}') in VU
        assert b"db-01.acme.internal" not in VU[-1][1]
        assert "restaure" in r.text
    finally:
        proxy.stop()


def test_a_rewritten_body_gets_the_right_length(
        interception, autorite_origine, origine):
    """Un substitut n'a pas la longueur de la valeur réelle. Garder l'ancien
    `content-length` tronque le corps ou fait attendre l'origine — et le
    symptôme est un blocage, pas une erreur."""
    class Allonge:
        def outgoing(self, host, headers, body):
            return body + b'{"suffixe": "beaucoup-plus-long-que-avant"}'

        def incoming(self, host, headers, body):
            return body

    VU.clear()
    proxy = _proxy(interception, autorite_origine, Allonge())
    try:
        with _client(proxy, interception) as client:
            client.post(f"https://127.0.0.1:{origine}/rpc", content=b"{}")
        assert VU[-1][1].endswith(b'beaucoup-plus-long-que-avant"}')
    finally:
        proxy.stop()


def test_an_unverifiable_upstream_certificate_is_refused(
        interception, autorite_origine, origine):
    """Intercepter ne doit pas AFFAIBLIR ce qu'on remplace. Sans vérification
    amont, le proxy déchiffre puis fait confiance à n'importe qui : la surface
    d'attaque a changé de place, elle n'a pas disparu."""
    proxy = ForwardProxy(ForwardPolicy(inspect=["127.0.0.1"], tunnel=[]),
                         interception,
                         upstream_context=ssl.create_default_context())
    proxy.start_in_thread()
    try:
        with _client(proxy, interception) as client:
            with pytest.raises(httpx.HTTPError):
                client.get(f"https://127.0.0.1:{origine}/salut")
        assert any("certificat" in d.reason for d in proxy.decisions), \
            proxy.decisions
    finally:
        proxy.stop()


def test_a_stream_we_cannot_rewrite_is_refused_not_relayed(
        interception, autorite_origine, origine):
    """Relayer intact une réponse en flux, sur une destination déclarée À
    INSPECTER, serait un fail-open silencieux."""
    proxy = _proxy(interception, autorite_origine)
    try:
        with _client(proxy, interception) as client:
            r = client.get(f"https://127.0.0.1:{origine}/flux")
        assert r.status_code == 502
        assert any("flux" in d.reason for d in proxy.decisions), proxy.decisions
    finally:
        proxy.stop()


def test_a_reused_connection_carries_several_requests(
        interception, autorite_origine, origine):
    """Un agent réutilise sa connexion des dizaines de fois. Ne traiter que la
    première requête laisserait la session se figer sur la deuxième."""
    proxy = _proxy(interception, autorite_origine)
    try:
        with _client(proxy, interception) as client:
            un = client.get(f"https://127.0.0.1:{origine}/un")
            deux = client.get(f"https://127.0.0.1:{origine}/deux")
        assert un.json()["chemin"] == "/un"
        assert deux.json()["chemin"] == "/deux"
    finally:
        proxy.stop()
