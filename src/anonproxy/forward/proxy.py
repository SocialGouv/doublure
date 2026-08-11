"""An HTTP forward proxy — the chokepoint `ANTHROPIC_BASE_URL` cannot be.

A base-URL setting redirects one client's calls to one API. Everything else an
agent opens ignores it: remote MCP servers, package registries, a vendor's tool
API. Phase 0 measured four such destinations against the one that honours it —
and captured all four **through an explicit proxy**, which is what makes this
module possible rather than theoretical.

Two things it does today:

- it **decides before connecting**. An unlisted destination gets no socket at
  all, and the client is told so rather than left to time out;
- it **relays a tunnelled destination untouched**, so the client validates the
  origin's own certificate. A tunnel that quietly interposed itself would be
  the interception it is defined not to be.

And one thing it deliberately does NOT do yet: a destination marked `INSPECT`
is **refused**, not relayed in the clear. Relaying it would mean the operator
asked for the payload to be read, nothing read it, and nothing said so — a
silent fail-open, which is the one failure mode this project treats as
unacceptable.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import threading
from dataclasses import dataclass
from typing import Protocol

from .ca import InterceptionCA
from .policy import ForwardPolicy, Verdict

logger = logging.getLogger("anonproxy.forward")

#: Au-delà, un en-tête de requête n'est plus une requête mais une charge.
_MAX_ENTETE = 64 * 1024
_MORCEAU = 64 * 1024
#: Un corps plus gros n'est pas pseudonymisable en mémoire ; le refuser est
#: plus honnête que de le relayer sans l'avoir lu.
_MAX_CORPS = 32 * 1024 * 1024
#: Ces réponses n'ont pas de corps, quoi que disent leurs en-têtes.
_SANS_CORPS = {204, 304}
#: Au-delà, une remorque n'est plus une remorque mais un déni de service.
_MAX_REMORQUE = 64
#: Sans un seul octet pendant ce délai, l'échange est abandonné. C'est une
#: INACTIVITÉ, jamais une durée : un gros corps lent reste licite tant qu'il
#: arrive, et un appel d'outil qui calcule une minute avant de répondre aussi.
_INACTIVITE = 120.0


@dataclass(frozen=True)
class Decision:
    """Ce que le proxy a fait d'une destination, et pourquoi."""
    destination: str
    verdict: Verdict
    reason: str


class BodyTransform(Protocol):
    """Ce que le proxy fait des corps qu'il a pu lire.

    Deux sens, jamais confondus : ce qui SORT est pseudonymisé, ce qui ENTRE
    est restauré. Le même texte n'a pas le même traitement selon la direction,
    et c'est toute la réversibilité du canal.
    """

    def outgoing(self, host: str, headers: dict[str, str], body: bytes) -> bytes: ...

    def incoming(self, host: str, headers: dict[str, str], body: bytes) -> bytes: ...


class _SansEffet:
    """Lit sans réécrire. Utile pour observer un canal ; ne protège rien, et
    c'est pour ça que l'appelant doit fournir sa transformation."""

    def outgoing(self, host, headers, body):
        return body

    def incoming(self, host, headers, body):
        return body


class ForwardProxy:
    def __init__(self, policy: ForwardPolicy, ca: InterceptionCA, *,
                 host: str = "127.0.0.1", port: int = 0,
                 upstream_context: ssl.SSLContext | None = None,
                 transform: "BodyTransform | None" = None,
                 idle_timeout: float = _INACTIVITE):
        self.policy = policy
        self.ca = ca
        self.host = host
        self._port = port
        self._inactivite = idle_timeout
        #: Le contexte AMONT vérifie le vrai certificat de la destination.
        #: Il n'existe volontairement aucun réglage pour ne pas vérifier :
        #: intercepter ne doit pas AFFAIBLIR ce qu'on remplace, sinon le proxy
        #: déchiffre puis fait confiance à n'importe qui, et la surface
        #: d'attaque a seulement changé de place.
        self.upstream_context = upstream_context or ssl.create_default_context()
        self.transform = transform or _SansEffet()
        self.decisions: list[Decision] = []
        self._boucle: asyncio.AbstractEventLoop | None = None
        self._serveur: asyncio.base_events.Server | None = None
        self._fil: threading.Thread | None = None
        self._pret = threading.Event()

    # ------------------------------------------------------------------ cycle

    @property
    def port(self) -> int:
        if self._serveur is None:
            raise RuntimeError("proxy non démarré")
        return self._serveur.sockets[0].getsockname()[1]

    def start_in_thread(self) -> None:
        """Démarre le proxy dans son propre fil et rend la main quand il écoute.

        Rendre la main AVANT que le port n'écoute ferait échouer la première
        requête d'un client par une course, et le symptôme se lirait comme un
        refus.
        """
        self._fil = threading.Thread(target=self._servir, daemon=True)
        self._fil.start()
        if not self._pret.wait(timeout=10):
            raise RuntimeError("le proxy sortant n'a pas démarré")

    def _servir(self) -> None:
        self._boucle = asyncio.new_event_loop()
        asyncio.set_event_loop(self._boucle)
        self._boucle.run_until_complete(self._ouvrir())
        self._pret.set()
        self._boucle.run_forever()

    async def _ouvrir(self) -> None:
        self._serveur = await asyncio.start_server(
            self._client, self.host, self._port, limit=_MAX_ENTETE)

    def stop(self, timeout: float = 5) -> None:
        """Ferme l'écoute, annule ce qui est en vol, PUIS arrête la boucle.

        Arrêter la boucle d'abord détruit les tâches encore en cours : les
        connexions sont avortées au milieu d'une réponse et les sockets restent
        ouvertes le temps du ramassage. Le symptôme, côté agent, est une
        requête qui meurt sans raison.
        """
        if self._boucle is None or self._boucle.is_closed():
            return
        fin = asyncio.run_coroutine_threadsafe(self._fermer(), self._boucle)
        try:
            fin.result(timeout)
        except (TimeoutError, RuntimeError):
            pass  # l'arrêt qui suit reste la garantie de terminaison
        self._boucle.call_soon_threadsafe(self._boucle.stop)
        if self._fil is not None:
            self._fil.join(timeout=timeout)
        self._boucle.close()

    async def _fermer(self) -> None:
        if self._serveur is not None:
            self._serveur.close()
            await self._serveur.wait_closed()
        en_vol = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for tache in en_vol:
            tache.cancel()
        await asyncio.gather(*en_vol, return_exceptions=True)

    # ----------------------------------------------------------------- requête

    async def _client(self, lecteur: asyncio.StreamReader,
                      ecrivain: asyncio.StreamWriter) -> None:
        try:
            entete = await self._lire_entete(lecteur)
            if entete is None:
                return
            ligne = entete.split(b"\r\n", 1)[0].decode("latin-1")
            methode, _, reste = ligne.partition(" ")
            cible = reste.rpartition(" ")[0].strip() or reste.strip()
            if methode.upper() == "CONNECT":
                await self._connect(cible, lecteur, ecrivain)
            else:
                # Forme absolue (`GET http://hôte/…`) : ni tunnelable ni
                # lisible tant que l'interception n'existe pas.
                await self._refuser(
                    ecrivain, cible,
                    "requête en clair : l'interception n'est pas encore "
                    "implémentée, ce proxy ne relaie rien qu'il ne peut lire")
        except (ConnectionError, asyncio.IncompleteReadError,
                asyncio.CancelledError):
            pass
        finally:
            ecrivain.close()

    async def _lire_entete(self, lecteur: asyncio.StreamReader) -> bytes | None:
        try:
            return await lecteur.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError:
            return None
        except asyncio.IncompleteReadError:
            return None

    async def _connect(self, destination: str, lecteur: asyncio.StreamReader,
                       ecrivain: asyncio.StreamWriter) -> None:
        verdict = self.policy.verdict(destination)
        if verdict is Verdict.REFUSE:
            await self._refuser(ecrivain, destination,
                                "destination non déclarée (fail-closed)")
            return
        if verdict is Verdict.INSPECT:
            await self._inspecter(destination, lecteur, ecrivain)
            return

        hote, _, port = destination.rpartition(":")
        try:
            amont_l, amont_e = await asyncio.open_connection(
                hote.strip("[]"), int(port))
        except (OSError, ValueError, OverflowError) as exc:
            await self._refuser(ecrivain, destination,
                                f"connexion impossible : {exc}",
                                verdict=Verdict.TUNNEL)
            return

        self._tracer(destination, Verdict.TUNNEL, "relayé sans être lu")
        ecrivain.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await ecrivain.drain()
        await self._relayer(lecteur, ecrivain, amont_l, amont_e)

    # -------------------------------------------------------------- inspection

    async def _inspecter(self, destination: str, lecteur: asyncio.StreamReader,
                         ecrivain: asyncio.StreamWriter) -> None:
        """Termine le TLS du client, ouvre le sien vers l'amont, relit tout.

        L'amont est joint AVANT de répondre 200 : un certificat qu'on ne peut
        pas vérifier doit se solder par un refus de proxy en clair, que le
        client comprend, plutôt que par une erreur TLS après coup — dont il ne
        pourrait pas dire si elle vient de nous ou de la destination.
        """
        hote, _, port = destination.rpartition(":")
        hote = hote.strip("[]")
        ouvert = await self._ouvrir_amont(hote, port, ecrivain, destination,
                                          en_clair=True)
        if ouvert is None:
            return
        amont_l, amont_e = ouvert

        self._tracer(destination, Verdict.INSPECT, "corps lus et réécrits")
        ecrivain.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await ecrivain.drain()
        try:
            await ecrivain.start_tls(self.ca.server_context(hote))
        except (ssl.SSLError, OSError):
            amont_e.close()
            return  # le client a refusé notre feuille : rien à dire en clair

        # UNE connexion amont PAR ÉCHANGE. Le tour 6 avait fermé la fenêtre
        # courte du vol de réponse en vérifiant que le tampon amont était vide ;
        # un amont qui attend 150 ms avant de glisser sa fausse réponse la
        # rouvrait — 10 vols sur 10 mesurés. Contrôler un état qui bouge ne
        # ferme pas la classe ; ne rien réutiliser la ferme. Le client, lui,
        # garde sa connexion : c'est nous qui ne recyclons pas la nôtre.
        # L'amont est ouvert PARESSEUSEMENT, après avoir lu la requête : ouvrir
        # avant de savoir si le client en enverra une autre faisait payer N+1
        # poignées de main pour N requêtes, et sur un amont à quota la
        # dernière — inutile — peut faire refuser la suivante, qui est vraie.
        amont_e.close()
        try:
            while True:
                # Seule lecture volontairement SANS délai : ici le client est
                # notre agent, qui garde sa connexion ouverte entre deux tours
                # et peut ne rien dire pendant que l'opérateur réfléchit. Aucun
                # amont n'est tenu à ce moment — la fermer coûterait une
                # poignée de main à chaque pause. Dès que la requête est là,
                # tout ce qui suit est borné.
                requete = await self._lire_entete(lecteur)
                if not requete:
                    return
                ouvert = await self._ouvrir_amont(hote, int(port), ecrivain,
                                                  destination)
                if ouvert is None:
                    return
                amont_l, amont_e = ouvert
                try:
                    encore = await self._echange(hote, destination, requete,
                                                 lecteur, ecrivain,
                                                 amont_l, amont_e)
                finally:
                    amont_e.close()
                if not encore:
                    return
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — voir le commentaire
            # Énumérer les types d'exception a échoué DEUX fois : le tour 7 a
            # converti les cinq qu'il avait sous les yeux et laissé passer
            # `IncompleteReadError` et `OverflowError`. Ce qui reste est
            # d'attraper ce qui n'était pas prévu — et de le NOMMER, pour que
            # le refus soit visible au lieu d'être une socket coupée.
            await self._echouer(ecrivain, destination,
                                f"échange interrompu : {type(exc).__name__}: {exc}")

    async def _ouvrir_amont(self, hote: str, port, ecrivain, destination: str,
                            *, en_clair: bool = False):
        """Ouvre l'amont, en VÉRIFIANT son certificat. None si c'est refusé.

        `en_clair` : avant la réponse 200, le refus part en HTTP lisible, que
        le client comprend. Après, il n'y a plus que le tunnel.
        """
        try:
            return await asyncio.open_connection(
                hote, int(port), ssl=self.upstream_context, server_hostname=hote)
        except ssl.SSLCertVerificationError as exc:
            raison = f"certificat amont invérifiable : {exc.verify_message or exc}"
        except (OSError, ValueError, OverflowError) as exc:
            raison = f"connexion impossible : {exc}"
        if en_clair:
            await self._refuser(ecrivain, destination, raison,
                                verdict=Verdict.INSPECT)
        else:
            await self._echouer(ecrivain, destination, raison)
        return None

    async def _echange(self, hote: str, destination: str, requete: bytes,
                       cl: asyncio.StreamReader, ce: asyncio.StreamWriter,
                       al: asyncio.StreamReader, ae: asyncio.StreamWriter) -> bool:
        """Une requête, une réponse. Rend True si la connexion peut resservir.

        Un agent réutilise sa connexion des dizaines de fois : ne traiter que
        la première requête figerait la session sur la deuxième.
        """
        try:
            ligne, entetes = _analyser(requete)
            methode = ligne.split(" ", 1)[0].upper()
            corps = await self._lire_corps(cl, entetes, reponse=False)
        except _CorpsIllisible as exc:
            await self._echouer(ce, destination, str(exc))
            return False

        corps = self.transform.outgoing(hote, entetes, corps)
        ae.write(_reconstruire(ligne, entetes, corps, avec_corps=bool(corps)))
        await ae.drain()

        try:
            reponse = await self._attendre(self._lire_entete(al),
                                           "l'amont n'a pas répondu")
            if not reponse:
                return False
            ligne_r, entetes_r = _analyser(reponse)
        except _CorpsIllisible as exc:
            await self._echouer(ce, destination, str(exc))
            return False
        try:
            statut = int(ligne_r.split(" ")[1])
        except (IndexError, ValueError):
            # Remontait jusqu'à `_client`, qui ne l'attrapait pas : la tâche
            # mourait et le client voyait sa socket coupée sans un mot.
            await self._echouer(ce, destination,
                                f"ligne de statut amont illisible : {ligne_r!r}")
            return False
        if methode == "HEAD" or statut in _SANS_CORPS:
            ce.write(_reconstruire(ligne_r, entetes_r, b"", avec_corps=False))
            await ce.drain()
            # La connexion amont N'EST PAS réutilisée : un amont qui envoie
            # malgré tout un corps sur un 204 laisse ces octets dans le
            # tampon, et ils fabriquent la réponse suivante. Drainer
            # supposerait que ses en-têtes disent la vérité ; fermer ne
            # suppose rien.
            return False
        try:
            corps_r = await self._lire_corps(al, entetes_r)
        except _CorpsIllisible as exc:
            await self._echouer(ce, destination, str(exc))
            return False

        if _residu_amont(al):
            # L'amont a envoyé PLUS que la réponse demandée. Ces octets
            # deviendraient la réponse à la requête SUIVANTE — c'est le vol de
            # réponse : un serveur hostile choisit alors ce que l'agent croit
            # avoir reçu. On ne devine pas ce que c'est, on ferme.
            await self._echouer(
                ce, destination,
                "l'amont a envoyé plus que la réponse demandée : "
                "connexion désynchronisée, elle ne sera pas réutilisée")
            return False

        corps_r = self.transform.incoming(hote, entetes_r, corps_r)
        ce.write(_reconstruire(ligne_r, entetes_r, corps_r, avec_corps=True))
        await ce.drain()
        return _peut_resservir(entetes, entetes_r)

    async def _lire_corps(self, lecteur: asyncio.StreamReader,
                          entetes: dict[str, str], *,
                          reponse: bool = True) -> bytes:
        if "chunked" in entetes.get("transfer-encoding", "").lower():
            return await self._lire_morceaux(lecteur)
        if (taille := entetes.get("content-length")) is not None:
            # `int()` qui échoue, ou un nombre NÉGATIF passé à `readexactly` :
            # deux exceptions qui n'étaient pas `_CorpsIllisible`, donc qui
            # remontaient jusqu'à la tâche et tuaient le tunnel sans un mot.
            try:
                n = int(taille)
            except ValueError as exc:
                raise _CorpsIllisible(
                    f"content-length illisible : {taille!r}") from exc
            if n < 0:
                raise _CorpsIllisible(f"content-length négatif : {n}")
            if n > _MAX_CORPS:
                raise _CorpsIllisible(
                    f"corps de {n} octets : au-delà de ce qui peut être relu")
            return await self._lire_exactement(lecteur, n) if n else b""
        if reponse and ("content-type" in entetes
                        or entetes.get("connection", "").lower() == "close"):
            # Ni longueur ni découpage : la fin du corps est la fermeture de la
            # connexion — un FLUX. On ne sait pas encore le réécrire au fil de
            # l'eau, et le relayer intact sur une destination à INSPECTER
            # serait un fail-open silencieux.
            raise _CorpsIllisible(
                "réponse en flux (ni longueur ni découpage) : elle ne peut pas "
                "être relue, et la relayer intacte serait un fail-open")
        return b""

    async def _attendre(self, lecture, attendu: str):
        """Borne une lecture par l'INACTIVITÉ de sa source.

        Un amont qui se TAIT au milieu d'un échange n'est pas une troncature :
        il tient la ligne et n'envoie plus rien. Sans délai, l'agent attendait
        cette réponse sans fin — le pire des symptômes, parce qu'il ne
        ressemble à aucune panne et qu'aucune erreur ne le nomme.
        """
        try:
            return await asyncio.wait_for(lecture, self._inactivite)
        except TimeoutError as exc:
            raise _CorpsIllisible(
                f"{attendu} : plus un octet depuis {self._inactivite:g} s, "
                "l'échange est abandonné") from exc

    async def _lire_exactement(self, lecteur: asyncio.StreamReader,
                               n: int) -> bytes:
        """`readexactly`, borné par l'INACTIVITÉ et non par la durée.

        `wait_for(readexactly(n))` bornerait la durée TOTALE : un gros corps
        qui arrive lentement — mais qui arrive — serait coupé au milieu, et le
        symptôme se lirait comme une panne d'amont. On lit morceau par morceau,
        et c'est l'absence d'octet qui fait échouer, jamais la lenteur.

        Au passage, une troncature devient un refus NOMMÉ : `readexactly` levait
        une `IncompleteReadError` que seule la garde large de l'inspection
        rattrapait, sous un message qui ne disait pas ce qui manquait.
        """
        morceaux = bytearray()
        while len(morceaux) < n:
            morceau = await self._attendre(
                lecteur.read(min(_MORCEAU, n - len(morceaux))),
                f"corps de {n} octets annoncés")
            if not morceau:
                raise _CorpsIllisible(
                    f"corps tronqué : {len(morceaux)} octets reçus sur {n}")
            morceaux += morceau
        return bytes(morceaux)

    async def _ligne(self, lecteur: asyncio.StreamReader) -> bytes:
        """Une ligne, ou un refus. `LimitOverrunError` n'hérite pas de
        `ConnectionError` : elle traversait tout et tuait la tâche."""
        try:
            return await self._attendre(lecteur.readuntil(b"\r\n"),
                                        "ligne de découpage attendue")
        except asyncio.LimitOverrunError as exc:
            raise _CorpsIllisible(f"ligne démesurée : {exc}") from exc

    async def _lire_morceaux(self, lecteur: asyncio.StreamReader) -> bytes:
        morceaux = bytearray()
        while True:
            ligne = (await self._ligne(lecteur)).strip()
            try:
                # Sans le `or b"0"` d'origine : une ligne VIDE passait pour la
                # marque de fin, le corps était tronqué en silence et le reste
                # laissé dans le tampon.
                taille = int(ligne.split(b";", 1)[0], 16)
            except ValueError as exc:
                raise _CorpsIllisible(
                    f"taille de morceau illisible : {ligne!r}") from exc
            if taille < 0:
                # `int(b"-5", 16)` vaut -5 sans lever : c'est `readexactly` qui
                # tombait, plus loin et sans être rattrapé.
                raise _CorpsIllisible(f"taille de morceau négative : {taille}")
            if taille == 0:
                # Une remorque est `*(field-line CRLF) CRLF`. N'en consommer
                # qu'UNE ligne laissait le reste dans le tampon, et ce reste
                # devenait la « réponse » à la requête SUIVANTE : un amont
                # hostile choisissait ce que l'agent croyait avoir reçu.
                # Le commentaire d'origine promettait « puis ligne vide » ; le
                # code ne la lisait pas.
                for _ in range(_MAX_REMORQUE):
                    if await self._ligne(lecteur) == b"\r\n":
                        return bytes(morceaux)
                raise _CorpsIllisible("remorque interminable : framing refusé")
            if len(morceaux) + taille > _MAX_CORPS:
                raise _CorpsIllisible("corps découpé au-delà de la taille relisible")
            morceaux += await self._lire_exactement(lecteur, taille)
            await self._lire_exactement(lecteur, 2)  # CRLF de fin de morceau

    async def _echouer(self, ecrivain: asyncio.StreamWriter, destination: str,
                       raison: str) -> None:
        """Erreur DANS le tunnel TLS : le client l'a chiffrée, il la lira."""
        self._tracer(destination, Verdict.INSPECT, raison)
        corps = raison.encode("utf-8")
        ecrivain.write(
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"content-type: text/plain; charset=utf-8\r\n"
            b"content-length: " + str(len(corps)).encode() + b"\r\n"
            b"connection: close\r\n\r\n" + corps)
        try:
            await ecrivain.drain()
        except ConnectionError:
            pass

    async def _relayer(self, cl: asyncio.StreamReader, ce: asyncio.StreamWriter,
                       al: asyncio.StreamReader, ae: asyncio.StreamWriter) -> None:
        """Tunnel : sans délai, et c'est la seule réponse honnête ici.

        Un tunnel est opaque par définition — on ne sait pas où finit un
        échange, donc un silence peut être une connexion morte comme un flux
        long-courrier parfaitement licite. Couper au bout de N secondes
        casserait les seconds sans rien prouver sur les premiers. C'est ce que
        l'inspection achète en plus : elle sait ce qu'elle attend.
        """

        async def pomper(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
            try:
                while morceau := await src.read(_MORCEAU):
                    dst.write(morceau)
                    await dst.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                # Fermer l'écriture, pas la connexion : l'autre sens peut avoir
                # encore des octets à livrer, et les couper tronque la réponse.
                try:
                    dst.write_eof()
                except (OSError, RuntimeError):
                    pass

        await asyncio.gather(pomper(cl, ae), pomper(al, ce))
        ae.close()

    async def _refuser(self, ecrivain: asyncio.StreamWriter, destination: str,
                       raison: str, verdict: Verdict = Verdict.REFUSE) -> None:
        self._tracer(destination, verdict, raison)
        corps = raison.encode("utf-8")
        ecrivain.write(
            b"HTTP/1.1 403 Forbidden\r\n"
            b"content-type: text/plain; charset=utf-8\r\n"
            b"content-length: " + str(len(corps)).encode() + b"\r\n"
            b"connection: close\r\n\r\n" + corps)
        try:
            await ecrivain.drain()
        except ConnectionError:
            pass

    def _tracer(self, destination: str, verdict: Verdict, raison: str) -> None:
        self.decisions.append(Decision(destination, verdict, raison))
        logger.info("forward %s -> %s (%s)", destination, verdict.value, raison)


class _CorpsIllisible(RuntimeError):
    """Ce corps ne peut pas être relu, donc pas réécrit, donc pas relayé."""


def _analyser(entete: bytes) -> tuple[str, dict[str, str]]:
    lignes = entete.decode("latin-1").split("\r\n")
    # UNE règle pour toute la tête, et c'est là qu'est le correctif. Le
    # découpage se fait sur `\r\n` : tout `\r` ou `\n` qui SURVIT est donc un
    # terminateur nu, recopié tel quel par `_reconstruire`, et un client qui
    # l'accepte comme fin de ligne — la RFC 7230 le tolère — lit un en-tête
    # injecté par l'amont.
    #
    # Ce contrôle a été écrit TROIS fois : les valeurs au tour 7, la ligne de
    # statut au tour 8, les NOMS ici — `x-innocent\rset-cookie: PWN=1` était
    # analysé sans broncher. À chaque fois il visait un endroit au lieu de la
    # classe. Une seule condition sur toutes les lignes n'a pas de jumelle.
    #
    # Le refus ne CITE PAS la ligne fautive. Une première version la recopiait
    # « pour aider » : l'en-tête injecté revenait alors au client dans le corps
    # du 502, par la porte du refus lui-même. Le rang suffit à diagnostiquer, et
    # ne rend rien de ce que l'amont a écrit.
    for rang, ligne in enumerate(lignes):
        if "\n" in ligne or "\r" in ligne:
            quoi = "ligne de statut" if rang == 0 else f"en-tête n°{rang}"
            raise _CorpsIllisible(
                f"caractère de contrôle interdit dans la tête ({quoi})")
    entetes: dict[str, str] = {}
    for ligne in lignes[1:]:
        nom, _, valeur = ligne.partition(":")
        if nom.strip():
            # Comparés en minuscules : HTTP les déclare insensibles à la casse,
            # et `Content-Length` doit décider comme `content-length`.
            entetes[nom.strip().lower()] = valeur.strip()
    return lignes[0], entetes


def _reconstruire(ligne: str, entetes: dict[str, str], corps: bytes,
                  *, avec_corps: bool) -> bytes:
    """Réécrit l'en-tête pour le corps qu'on a produit.

    Un substitut n'a pas la longueur de la valeur réelle : garder l'ancienne
    tronque le corps ou fait attendre le destinataire, et le symptôme est un
    blocage, pas une erreur. Le découpage disparaît en même temps — on renvoie
    un corps entier.
    """
    sortants = {n: v for n, v in entetes.items()
                if n not in ("content-length", "transfer-encoding")}
    if avec_corps:
        sortants["content-length"] = str(len(corps))
    tete = ligne + "\r\n" + "".join(
        f"{n}: {v}\r\n" for n, v in sortants.items()) + "\r\n"
    return tete.encode("latin-1") + corps


def _residu_amont(lecteur: asyncio.StreamReader) -> bool:
    """Reste-t-il des octets que l'amont a envoyés sans qu'on les demande ?

    `StreamReader` n'expose pas sa file. On touche cet attribut privé plutôt
    que d'attendre un délai à chaque échange : c'est le seul moyen GRATUIT de
    voir un résidu, et un résidu devient la réponse à la requête suivante.

    S'il disparaît d'une version de Python, on lève : perdre ce contrôle en
    silence rouvrirait le vol de réponse sans que rien ne le dise.
    """
    file = getattr(lecteur, "_buffer", None)
    if file is None:
        raise RuntimeError(
            "StreamReader sans `_buffer` : la détection de résidu amont ne "
            "fonctionne plus. Refus plutôt que silence.")
    return bool(file)


def _peut_resservir(requete: dict[str, str], reponse: dict[str, str]) -> bool:
    return "close" not in (requete.get("connection", "").lower()
                           + reponse.get("connection", "").lower())
