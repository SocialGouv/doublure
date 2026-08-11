"""Re-reading HTTP is where the interception breaks, not TLS.

Round 6 attacked this surface and every finding landed here: the certificate
chain held, the framing did not. The worst is **response smuggling** — an
upstream leaves bytes in the buffer, and the proxy serves them as the answer to
the CLIENT'S NEXT REQUEST. In this system the client is the agent, so a hostile
MCP server chooses what tool result the agent believes.

None of these leak a value. All of them let a third party decide what the agent
reads, which is the same anti-pattern as trusting the model to behave.

The upstream here is scripted at the BYTE level: no HTTP library would emit a
malformed trailer or a body on a 204, and that is exactly why a library-based
test proved nothing.
"""
from __future__ import annotations

import socket
import ssl
import threading

import pytest

from anonproxy.forward.ca import InterceptionCA
from anonproxy.forward.policy import ForwardPolicy
from anonproxy.forward.proxy import ForwardProxy


@pytest.fixture(scope="module")
def interception(tmp_path_factory):
    ca = InterceptionCA(tmp_path_factory.mktemp("etat-i"))
    ca.ensure()
    return ca


@pytest.fixture(scope="module")
def autorite_origine(tmp_path_factory):
    ca = InterceptionCA(tmp_path_factory.mktemp("etat-o"))
    ca.ensure()
    return ca


class OrigineScriptee:
    """Amont qui répond des OCTETS choisis, une réponse par requête reçue."""

    def __init__(self, ca: InterceptionCA, tmp_path, reponses: list[bytes]):
        cert_pem, cle_pem = ca.leaf_for("127.0.0.1")
        pem = tmp_path / "o.pem"
        pem.write_bytes(cert_pem + cle_pem)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile=str(pem))
        self.reponses = list(reponses)
        self.appels = 0
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._servir, daemon=True).start()

    def _servir(self):
        while True:
            try:
                brut, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._connexion, args=(brut,),
                             daemon=True).start()

    def _connexion(self, brut):
        try:
            tls = self.ctx.wrap_socket(brut, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            while True:
                entete = b""
                while b"\r\n\r\n" not in entete:
                    morceau = tls.recv(4096)
                    if not morceau:
                        return
                    entete += morceau
                self.appels += 1
                if not self.reponses:
                    return
                tls.sendall(self.reponses.pop(0))
        except OSError:
            pass
        finally:
            tls.close()


def _monter(interception, autorite_origine, tmp_path, reponses):
    origine = OrigineScriptee(autorite_origine, tmp_path, reponses)
    proxy = ForwardProxy(
        ForwardPolicy(inspect=["127.0.0.1"], tunnel=[]), interception,
        upstream_context=ssl.create_default_context(
            cafile=str(autorite_origine.cert_path)))
    proxy.start_in_thread()
    return origine, proxy


def _deux_requetes(proxy, interception, port) -> bytes:
    """Deux GET sur UNE connexion, en octets bruts : c'est la réutilisation
    qui porte le défaut, et un client de haut niveau la masque."""
    brut = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    brut.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
    reponse = b""
    while b"\r\n\r\n" not in reponse:
        reponse += brut.recv(4096)
    ctx = ssl.create_default_context(cafile=str(interception.cert_path))
    tls = ctx.wrap_socket(brut, server_hostname="127.0.0.1")
    tls.sendall(b"GET /un HTTP/1.1\r\nhost: x\r\n\r\n")
    recu = b""
    try:
        tls.settimeout(3)
        while len(recu) < 4096:
            morceau = tls.recv(4096)
            if not morceau:
                break
            recu += morceau
            if b"\r\n\r\n" in recu:
                tls.sendall(b"GET /deux HTTP/1.1\r\nhost: x\r\n\r\n")
    except (TimeoutError, OSError):
        pass
    finally:
        tls.close()
    return recu


def test_a_chunked_trailer_cannot_forge_the_next_response(
        interception, autorite_origine, tmp_path):
    """CRITIQUE. Un trailer est `*(field-line CRLF) CRLF` ; n'en consommer
    qu'UNE ligne laisse le reste dans le tampon, et il devient la « réponse »
    à la requête suivante. Un serveur MCP hostile choisit alors ce que l'agent
    croit avoir reçu."""
    piege = (b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
             b"transfer-encoding: chunked\r\nconnection: keep-alive\r\n\r\n"
             b"5\r\nhello\r\n0\r\nX-Trailer: peu-importe\r\n\r\n"
             b"HTTP/1.1 418 pwn\r\ncontent-length: 10\r\n\r\nCORPS_FAKE")
    vraie = (b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n"
             b"connection: keep-alive\r\n\r\nok")
    origine, proxy = _monter(interception, autorite_origine, tmp_path,
                             [piege, vraie])
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        assert b"418 pwn" not in recu, recu[:400]
        assert b"CORPS_FAKE" not in recu, recu[:400]
    finally:
        proxy.stop()


def test_a_body_on_a_204_cannot_forge_the_next_response(
        interception, autorite_origine, tmp_path):
    """HAUT. Même vol, sans trailer : un corps sur un 204 est interdit par la
    RFC et trivial à émettre. Non drainé, il pollue le tampon."""
    piege = (b"HTTP/1.1 204 No Content\r\nconnection: keep-alive\r\n\r\n"
             b"HTTP/1.1 418 pwn\r\ncontent-length: 10\r\n\r\nCORPS_FAKE")
    vraie = (b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n"
             b"connection: keep-alive\r\n\r\nok")
    origine, proxy = _monter(interception, autorite_origine, tmp_path,
                             [piege, vraie])
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        assert b"418 pwn" not in recu, recu[:400]
    finally:
        proxy.stop()


def test_an_empty_chunk_size_is_a_framing_error_not_an_end(
        interception, autorite_origine, tmp_path):
    """MOYEN. `int(b"" or b"0", 16)` faisait passer une ligne vide pour la fin
    des morceaux : le corps était TRONQUÉ en silence, et le reste laissé dans
    le tampon."""
    tronque = (b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n"
               b"transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
               b"5\r\nhello\r\n\r\n5\r\nworld\r\n0\r\n\r\n")
    origine, proxy = _monter(interception, autorite_origine, tmp_path,
                             [tronque])
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        # Soit le corps entier, soit un refus explicite — jamais un 200 qui
        # annonce cinq octets là où l'amont en a envoyé dix.
        assert b"hello" not in recu or b"world" in recu or b"502" in recu, \
            recu[:400]
    finally:
        proxy.stop()


def test_a_one_shot_request_with_connection_close_is_not_refused(
        interception, autorite_origine, tmp_path):
    """MOYEN, et c'est un FAUX POSITIF — dans un outil qui bloque, ça casse
    autant qu'une faille. `curl` et `wget` envoient `Connection: close` par
    défaut ; une requête sans longueur ni découpage a un corps VIDE, elle
    n'est pas un flux illisible."""
    vraie = (b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n"
             b"connection: close\r\n\r\nok")
    origine, proxy = _monter(interception, autorite_origine, tmp_path, [vraie])
    try:
        brut = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
        brut.sendall(
            f"CONNECT 127.0.0.1:{origine.port} HTTP/1.1\r\n\r\n".encode())
        reponse = b""
        while b"\r\n\r\n" not in reponse:
            reponse += brut.recv(4096)
        ctx = ssl.create_default_context(cafile=str(interception.cert_path))
        tls = ctx.wrap_socket(brut, server_hostname="127.0.0.1")
        tls.sendall(b"GET /un HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
        tls.settimeout(5)
        recu = tls.recv(4096)
        tls.close()
        assert b"502" not in recu, recu[:300]
        assert b"200 OK" in recu, recu[:300]
    finally:
        proxy.stop()
