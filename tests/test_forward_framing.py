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
    """Amont qui répond des OCTETS choisis, une réponse par requête reçue.

    Deux façons de mal finir, et il a fallu les distinguer pour les traiter :

    - `ferme_apres` coupe la connexion juste après avoir répondu — une
      TRONCATURE, qui arrive comme un EOF et se voit ;
    - `muette` tient la ligne ouverte et n'envoie plus rien — une ATTENTE, qui
      n'arrive jamais. C'est le défaut le plus long à trouver parce qu'il ne
      produit aucun symptôme : ni erreur, ni fermeture, ni octet.
    """

    def __init__(self, ca: InterceptionCA, tmp_path, reponses: list[bytes],
                 ferme_apres: bool = False, muette: bool = False,
                 lent: float = 0):
        self.ferme_apres = ferme_apres
        self.muette = muette
        self.lent = lent
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
                self._envoyer(tls, self.reponses.pop(0))
                if self.muette:
                    # Ne rien envoyer, ne rien fermer : le proxy doit décider
                    # tout seul que ça ne viendra pas.
                    threading.Event().wait(30)
                    return
                if self.ferme_apres:
                    return
        except OSError:
            pass
        finally:
            tls.close()

    def _envoyer(self, tls, reponse: bytes) -> None:
        """En un bloc, ou par à-coups si `lent`.

        Par à-coups, le corps met plus longtemps que le délai à arriver — mais
        il ARRIVE. C'est le cas licite qu'un bornage à la DURÉE couperait, et
        c'est exactement la moitié de la boucle qu'on oublie de tester.
        """
        if not self.lent:
            tls.sendall(reponse)
            return
        tete, _, corps = reponse.partition(b"\r\n\r\n")
        tls.sendall(tete + b"\r\n\r\n")
        for debut in range(0, len(corps), 4):
            threading.Event().wait(self.lent)
            tls.sendall(corps[debut:debut + 4])


def _monter(interception, autorite_origine, tmp_path, reponses,
            ferme_apres=False, muette=False, lent=0, idle_timeout=120.0):
    origine = OrigineScriptee(autorite_origine, tmp_path, reponses,
                              ferme_apres=ferme_apres, muette=muette,
                              lent=lent)
    proxy = ForwardProxy(
        ForwardPolicy(inspect=["127.0.0.1"], tunnel=[]), interception,
        upstream_context=ssl.create_default_context(
            cafile=str(autorite_origine.cert_path)),
        idle_timeout=idle_timeout)
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
    relance = False
    try:
        tls.settimeout(3)
        while len(recu) < 4096:
            morceau = tls.recv(4096)
            if not morceau:
                break
            recu += morceau
            if b"\r\n\r\n" in recu and not relance:
                # UNE seule fois : renvoyer à chaque tour faisait compter mes
                # propres requêtes comme des connexions amont du proxy.
                relance = True
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


# --------------------------------------------------------------------------- #
# Tour 7 — deux règles, pas cinq rustines
# --------------------------------------------------------------------------- #


class OrigineRetardee(OrigineScriptee):
    """Amont qui envoie sa réponse, ATTEND, puis glisse la suivante.

    Le contrôle de résidu du tour 6 lit un état qui bouge : il ferme la fenêtre
    courte (octets collés à la réponse) et laisse la longue, plus facile à
    provoquer. Mesuré : 10 vols sur 10.
    """

    def _connexion(self, brut):
        import time
        try:
            tls = self.ctx.wrap_socket(brut, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            entete = b""
            while b"\r\n\r\n" not in entete:
                morceau = tls.recv(4096)
                if not morceau:
                    return
                entete += morceau
            self.appels += 1
            tls.sendall(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n"
                        b"connection: keep-alive\r\n\r\nOK")
            time.sleep(0.15)
            tls.sendall(b"HTTP/1.1 418 pwn\r\ncontent-length: 10\r\n"
                        b"connection: keep-alive\r\n\r\nCORPS_FAKE")
            while True:
                if not tls.recv(4096):
                    return
        except OSError:
            pass


def test_a_delayed_smuggle_cannot_forge_the_next_response(
        interception, autorite_origine, tmp_path):
    """CRITIQUE. Contrôler un tampon à un instant T ne dit rien de T+150 ms.
    La règle qui ferme la CLASSE : on ne réutilise jamais une connexion
    amont — le résidu n'a alors nulle part où atterrir."""
    origine = OrigineRetardee(autorite_origine, tmp_path, [])
    proxy = ForwardProxy(
        ForwardPolicy(inspect=["127.0.0.1"], tunnel=[]), interception,
        upstream_context=ssl.create_default_context(
            cafile=str(autorite_origine.cert_path)))
    proxy.start_in_thread()
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        assert b"418 pwn" not in recu, recu[:400]
        assert b"CORPS_FAKE" not in recu, recu[:400]
    finally:
        proxy.stop()


@pytest.mark.parametrize("entete, corps", [
    (b"content-length: abc", b"x"),
    (b"content-length: -5", b"x"),
    (b"content-length:", b"x"),
    (b"transfer-encoding: chunked", b"-5\r\nxxxxx\r\n0\r\n\r\n"),
    (b"transfer-encoding: chunked", b"zz\r\nxxxxx\r\n0\r\n\r\n"),
])
def test_a_malformed_framing_answers_instead_of_dying(
        interception, autorite_origine, tmp_path, entete, corps):
    """HAUT, et c'est UNE famille : toute exception qui n'est pas
    `_CorpsIllisible` remontait jusqu'à la tâche asyncio, et le client sortait
    du tunnel sans un mot. Le tour 6 avait paré ce mode d'échec pour la ligne
    de statut — à UN endroit, alors qu'il était présent à cinq."""
    reponse = (b"HTTP/1.1 200 OK\r\n" + entete +
               b"\r\nconnection: close\r\n\r\n" + corps)
    origine, proxy = _monter(interception, autorite_origine, tmp_path,
                             [reponse])
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        assert recu, "le client n'a RIEN reçu : la tâche est morte en silence"
        assert b"502" in recu, recu[:300]
    finally:
        proxy.stop()


def test_a_header_value_cannot_carry_a_bare_newline(
        interception, autorite_origine, tmp_path):
    """MOYEN-HAUT. `\n` seul survivait au découpage (qui coupe sur `\r\n`) et
    était recopié tel quel. Un client qui accepte le `\n` seul comme
    terminateur — la RFC 7230 le permet — lit alors un en-tête que l'amont a
    injecté."""
    reponse = (b"HTTP/1.1 200 OK\r\n"
               b"content-type: text/html\nSet-Cookie: PWN=1; path=/\r\n"
               b"content-length: 2\r\nconnection: close\r\n\r\nok")
    origine, proxy = _monter(interception, autorite_origine, tmp_path,
                             [reponse])
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        # Exiger le 502 : sans lui, une tâche morte satisfait aussi
        # « pas de Set-Cookie », et le test passerait pour la mauvaise raison.
        assert recu, "le client n'a RIEN reçu : la tâche est morte en silence"
        assert b"Set-Cookie" not in recu, recu[:300]
        assert b"502" in recu, recu[:300]
    finally:
        proxy.stop()


# --------------------------------------------------------------------------- #
# Tour 8 — trois régressions du tour 7, dont sa JUMELLE
# --------------------------------------------------------------------------- #


def test_the_status_line_cannot_carry_a_bare_newline(
        interception, autorite_origine, tmp_path):
    """HAUT, et c'est LA JUMELLE. Le tour 7 a refusé les caractères de contrôle
    dans les VALEURS d'en-tête et laissé la ligne de STATUT, recopiée telle
    quelle. Chercher le jumeau fait partie du correctif, pas de la revue."""
    reponse = (b"HTTP/1.1 200 OK\nSet-Cookie: PWN=1; path=/\r\n"
               b"content-length: 2\r\nconnection: close\r\n\r\nok")
    origine, proxy = _monter(interception, autorite_origine, tmp_path,
                             [reponse])
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        assert recu, "tâche morte en silence"
        assert b"Set-Cookie" not in recu, recu[:300]
        assert b"502" in recu, recu[:300]
    finally:
        proxy.stop()


@pytest.mark.parametrize("reponse", [
    # Chunked annoncé, connexion coupée avant le premier morceau.
    b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
    # `content-length` menteur : 100 annoncés, 9 envoyés.
    b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\ntronquee!",
])
def test_an_upstream_that_cuts_early_answers_instead_of_dying(
        interception, autorite_origine, tmp_path, reponse):
    """HAUT. `IncompleteReadError` n'était pas convertie : elle traversait
    l'échange, traversait l'inspection, et `_client` l'avalait en silence.

    Le tour 7 avait annoncé fermer la CLASSE « aucune exception ne sort du
    tunnel sans un mot » — il l'avait fermée pour les cinq exceptions qu'il
    avait sous les yeux. Énumérer des types a échoué deux fois ; ce qui reste
    est d'attraper ce qui n'était pas prévu, en le NOMMANT."""
    origine, proxy = _monter(interception, autorite_origine, tmp_path,
                             [reponse], ferme_apres=True)
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        assert recu, "le client n'a RIEN reçu : la tâche est morte en silence"
        assert b"502" in recu, recu[:300]
    finally:
        proxy.stop()


def test_an_impossible_port_is_refused_not_hung(interception, tmp_path):
    """MOYEN. `open_connection` lève `OverflowError` sur un port hors bornes —
    ni `OSError` ni `ValueError`, donc hors de toutes les gardes."""
    proxy = ForwardProxy(ForwardPolicy(inspect=["127.0.0.1"], tunnel=[]),
                         interception)
    proxy.start_in_thread()
    try:
        brut = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
        brut.sendall(b"CONNECT 127.0.0.1:66666 HTTP/1.1\r\n\r\n")
        brut.settimeout(5)
        recu = brut.recv(4096)
        brut.close()
        assert recu, "aucune réponse : la tâche est morte"
        assert b"403" in recu or b"502" in recu, recu[:200]
    finally:
        proxy.stop()


def test_no_upstream_handshake_is_paid_for_a_request_never_sent(
        interception, autorite_origine, tmp_path):
    """MOYEN. La connexion amont s'ouvrait APRÈS l'échange, donc avant de
    savoir si le client en enverrait un autre : N requêtes coûtaient N+1
    poignées de main. Sur un amont à quota, la dernière — inutile — peut faire
    refuser la suivante, qui est vraie."""
    reponses = [b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n"
                b"connection: keep-alive\r\n\r\nok"] * 4
    origine, proxy = _monter(interception, autorite_origine, tmp_path,
                             reponses)
    try:
        _deux_requetes(proxy, interception, origine.port)
        assert origine.appels <= 2, (
            f"{origine.appels} connexions amont pour 2 requêtes client")
    finally:
        proxy.stop()


# --------------------------------------------------------------------------- #
# Le trou connu — un amont qui se TAIT n'est pas un amont qui coupe
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("reponse", [
    # Rien du tout : pas même une ligne de statut.
    b"",
    # Un corps annoncé qui n'arrivera jamais.
    b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n",
    # Un découpage ouvert, dont le morceau suivant n'arrivera jamais.
    b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n",
])
def test_an_upstream_that_goes_silent_is_given_up_on(
        interception, autorite_origine, tmp_path, reponse):
    """HAUT. Une TRONCATURE arrive comme un EOF et se voit ; un SILENCE
    n'arrive jamais. Il tient la ligne, n'envoie plus rien, et l'agent attend
    sa réponse sans fin — le pire des symptômes, parce qu'il ne ressemble à
    aucune panne et qu'aucune erreur ne le nomme.

    Les trois lectures amont sont couvertes : la ligne de statut, un corps à
    longueur annoncée, un corps découpé."""
    origine, proxy = _monter(interception, autorite_origine, tmp_path,
                             [reponse], muette=True, idle_timeout=0.5)
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        assert recu, "le client n'a RIEN reçu : il attend toujours"
        assert b"502" in recu, recu[:300]
    finally:
        proxy.stop()


def test_a_body_that_is_slow_but_arriving_is_not_cut(
        interception, autorite_origine, tmp_path):
    """L'AUTRE MOITIÉ, et c'est elle que le correctif pouvait casser.

    Borner la DURÉE d'une lecture aurait coupé un gros corps qui arrive
    lentement — mais qui arrive —, et le symptôme se serait lu comme une panne
    d'amont. Le délai porte sur l'INACTIVITÉ : chaque tranche le relance.
    Ici le corps met quatre fois le délai à arriver, et il doit passer."""
    corps = b"x" * 40  # dix tranches, une toutes les 0,2 s
    reponse = (b"HTTP/1.1 200 OK\r\ncontent-length: " +
               str(len(corps)).encode() + b"\r\nconnection: close\r\n\r\n" +
               corps)
    origine, proxy = _monter(interception, autorite_origine, tmp_path,
                             [reponse], lent=0.2, idle_timeout=0.5)
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        assert b"200 OK" in recu, recu[:300]
        assert corps in recu, recu[:300]
    finally:
        proxy.stop()


@pytest.mark.parametrize("tete", [
    # Dans le NOM d'un en-tête : jamais contrôlé jusqu'ici.
    b"HTTP/1.1 200 OK\r\nx-innocent\rset-cookie: PWN=1; path=/\r\n"
    b"content-length: 2\r\nconnection: close\r\n\r\nok",
    # Même chose avec un saut de ligne nu, que plus de clients acceptent.
    b"HTTP/1.1 200 OK\r\nx-innocent\nset-cookie: PWN=1; path=/\r\n"
    b"content-length: 2\r\nconnection: close\r\n\r\nok",
])
def test_a_header_name_cannot_carry_a_bare_terminator(
        interception, autorite_origine, tmp_path, tete):
    """HAUT, et c'est LA JUMELLE POUR LA TROISIÈME FOIS.

    Le tour 7 a refusé les caractères de contrôle dans les VALEURS d'en-tête,
    le tour 8 dans la ligne de STATUT. Les NOMS n'ont jamais été contrôlés :
    `x-innocent\\rset-cookie: PWN=1` était analysé sans broncher, recopié tel
    quel, et un client qui accepte le terminateur nu lisait l'en-tête injecté
    par l'amont. Vérifié : la clé du dictionnaire valait bien
    `'x-innocent\\rset-cookie'`.

    Le correctif ne vise pas le troisième endroit mais la CLASSE : le découpage
    se fait sur `\\r\\n`, donc tout `\\r` ou `\\n` qui survit dans N'IMPORTE
    quelle ligne de la tête est un terminateur nu. Une seule condition, plus de
    jumelle possible."""
    origine, proxy = _monter(interception, autorite_origine, tmp_path, [tete])
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        assert recu, "tâche morte en silence"
        assert b"502" in recu, recu[:300]
        assert b"set-cookie" not in recu.lower(), recu[:300]
    finally:
        proxy.stop()


def test_ordinary_headers_still_pass(interception, autorite_origine, tmp_path):
    """L'AUTRE MOITIÉ : la règle élargie ne doit refuser aucune tête normale."""
    normale = (b"HTTP/1.1 200 OK\r\ncontent-type: application/json; charset=utf-8"
               b"\r\nx-request-id: abc-123\r\ncontent-length: 2\r\n"
               b"connection: close\r\n\r\nok")
    origine, proxy = _monter(interception, autorite_origine, tmp_path, [normale])
    try:
        recu = _deux_requetes(proxy, interception, origine.port)
        assert b"200 OK" in recu, recu[:300]
        assert b"x-request-id: abc-123" in recu, recu[:300]
    finally:
        proxy.stop()
