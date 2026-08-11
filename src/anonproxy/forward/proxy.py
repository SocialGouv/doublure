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
import threading
from dataclasses import dataclass

from .ca import InterceptionCA
from .policy import ForwardPolicy, Verdict

logger = logging.getLogger("anonproxy.forward")

#: Au-delà, un en-tête de requête n'est plus une requête mais une charge.
_MAX_ENTETE = 64 * 1024
_MORCEAU = 64 * 1024


@dataclass(frozen=True)
class Decision:
    """Ce que le proxy a fait d'une destination, et pourquoi."""
    destination: str
    verdict: Verdict
    reason: str


class ForwardProxy:
    def __init__(self, policy: ForwardPolicy, ca: InterceptionCA, *,
                 host: str = "127.0.0.1", port: int = 0):
        self.policy = policy
        self.ca = ca
        self.host = host
        self._port = port
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
            await self._refuser(
                ecrivain, destination,
                "interception non implémentée : relayer en clair une "
                "destination à inspecter serait un fail-open silencieux",
                verdict=Verdict.INSPECT)
            return

        hote, _, port = destination.rpartition(":")
        try:
            amont_l, amont_e = await asyncio.open_connection(
                hote.strip("[]"), int(port))
        except (OSError, ValueError) as exc:
            await self._refuser(ecrivain, destination,
                                f"connexion impossible : {exc}",
                                verdict=Verdict.TUNNEL)
            return

        self._tracer(destination, Verdict.TUNNEL, "relayé sans être lu")
        ecrivain.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await ecrivain.drain()
        await self._relayer(lecteur, ecrivain, amont_l, amont_e)

    async def _relayer(self, cl: asyncio.StreamReader, ce: asyncio.StreamWriter,
                       al: asyncio.StreamReader, ae: asyncio.StreamWriter) -> None:
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
