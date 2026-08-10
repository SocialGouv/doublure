"""Proxy de pseudonymisation — canal 1 (trafic modèle).

Branchement : ``ANTHROPIC_BASE_URL=http://127.0.0.1:8090 claude``

Routes traitées :
  - ``POST /v1/messages``              (streaming et non-streaming)
  - ``POST /v1/messages/count_tokens`` (mêmes substitutions, sinon les
    estimations de Claude Code dérivent et la compaction se déclenche au
    mauvais moment)
Tout le reste (télémétrie, bootstrap, OAuth…) transite tel quel : le proxy ne
réécrit que ce qu'il comprend, et le harnais d'egress de la Phase 0 continue
de surveiller le reste.

Fail-closed : si le détecteur ou le coffre est indisponible, la requête est
refusée (502/503). Aucune donnée réelle ne part « en mode dégradé ».
"""
from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))  # anthropic_walker.py vit à la racine du dépôt

from anthropic_walker import SSERewriter, Substituter, walk_request, walk_response  # noqa: E402

from ..allowlist import Allowlist  # noqa: E402
from ..inventory import Inventory  # noqa: E402
from ..config import Settings, read_master_key  # noqa: E402
from ..detect import DetectClient, DetectionUnavailable  # noqa: E402
from ..annonce import injecter  # noqa: E402
from ..pipeline import Pseudonymizer  # noqa: E402
from ..policy import Policy  # noqa: E402
from ..sse import (  # noqa: E402
    FluxSSEInvalide, encode_sse, iter_blocks, parse_sse_block,
)
from ..surrogates.engine import SurrogateCollisionError, SurrogateEngine  # noqa: E402
from ..vault import Vault, VaultUnavailableError  # noqa: E402

logger = logging.getLogger("anonproxy")

#: En-têtes gérés par le transport : jamais recopiés tels quels.
_HOP_BY_HOP = {
    "host", "content-length", "connection", "keep-alive", "transfer-encoding",
    "upgrade", "proxy-authorization", "proxy-authenticate", "te", "trailer",
    "accept-encoding",  # httpx gère la négociation
}


def predicat_public(allowlist_file, inventory_file=None):
    """« Cette valeur est publique » — l'allowlist MOINS l'inventaire.

    `.is_exact` et non l'allowlist entière : une règle de FORME n'a pas de sens
    sur une sous-partie (cf. allowlist.py).

    L'inventaire PRIME, et c'est ce qui rend l'allowlist tenable : elle
    contient des mots courants (`code`, `run`, `error`), publics tant que
    l'opérateur n'a pas déclaré qu'une de ses machines porte ce nom. Il ne peut
    que REMONTER la protection, donc il ne peut pas introduire de fuite
    silencieuse — le seul mode d'échec du système qui ne se voie pas.

    Il était défini, documenté, testé… et lu par PERSONNE : le fichier existait
    et ne protégeait rien.
    """
    allow = Allowlist.load(allowlist_file)
    inv = Inventory.load(inventory_file)
    if not inv:
        return allow.is_exact
    return (lambda value, etype=None:
            allow.is_exact(value, etype) and not inv.est_a_nous(value))


class ProxyState:
    """Objets vivants du proxy (un par processus, une portée)."""

    def __init__(self, settings: Settings):
        self.settings = settings
        # Lue une seule fois : elle scelle le coffre ET dérive les substituts.
        master = read_master_key(settings.master_key_file)
        self.vault = Vault(settings.vault_path, master_key=master)
        self.policy = Policy(
            racine=settings.policy_dir, master_key=master,
            scope_key=settings.scope_key, session=settings.session_id,
        )
        self.engine = SurrogateEngine(
            vault=self.vault,
            master_key=master,
            scope_key=settings.scope_key,
            is_public=predicat_public(settings.allowlist_file),
            policy=self.policy,
            projet=settings.projet,
        )
        self.detector = DetectClient(
            settings.detect_url, regex_threshold=settings.regex_threshold
        )
        self.pseudonymizer = Pseudonymizer(
            self.detector, self.engine, cache_size=settings.cache_size
        )
        self.client = httpx.AsyncClient(
            base_url=settings.upstream_base,
            timeout=settings.request_timeout,
            verify=settings.ca_bundle or True,
        )
        self.unresolved_total = 0
        self._incoming: tuple[int, Substituter] | None = None

    def outgoing(self) -> Substituter:
        """Substituteur du sens sortant (réel → substituts)."""
        return Substituter(to_surrogate=self.pseudonymizer.to_surrogate)

    def incoming(self) -> Substituter:
        """Substituteur du sens entrant, vue coffre à jour (substituts → réel).

        Mémorisé tant que le coffre n'a pas changé : reconstruire l'objet à
        chaque requête forçait la recompilation de l'alternation regex de tous
        les substituts — ~19 ms par requête sur un coffre de 10 000 entrées, et
        ça croît linéairement. La lecture est sans état, l'instance se partage
        donc sans risque entre requêtes.
        """
        version = self.vault.version
        if self._incoming is not None and self._incoming[0] == version:
            return self._incoming[1]
        sub = Substituter(
            to_surrogate=lambda s: s, surrogates=self.pseudonymizer.surrogates_view()
        )
        self._incoming = (version, sub)
        return sub

    async def aclose(self) -> None:
        await self.client.aclose()
        self.detector.close()
        self.vault.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings.from_env()
    app.state.proxy = ProxyState(settings)
    logger.info(
        "proxy prêt — portée=%s upstream=%s détecteur=%s coffre=%d entrées",
        settings.scope_key, settings.upstream_base, settings.detect_url,
        app.state.proxy.vault.count(settings.scope_key),
    )
    try:
        yield
    finally:
        await app.state.proxy.aclose()


app = FastAPI(title="anonproxy", lifespan=lifespan)


# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #


def _forward_headers(request: Request) -> dict[str, str]:
    """En-têtes passés en l'état (x-api-key, anthropic-version/beta, OAuth…)."""
    return {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}


def _response_headers(upstream: httpx.Response) -> dict[str, str]:
    return {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in _HOP_BY_HOP | {"content-encoding"}
    }


def _fail(status: int, kind: str, detail: str) -> JSONResponse:
    """Erreur au format Anthropic — exploitable par le client sans le casser."""
    logger.error("%s: %s", kind, detail)
    return JSONResponse(
        status_code=status,
        content={"type": "error", "error": {"type": kind, "message": detail}},
    )


# --------------------------------------------------------------------------- #
# /v1/messages
# --------------------------------------------------------------------------- #


async def _pseudonymize(state: ProxyState, request: Request):
    """Lit le corps et le pseudonymise. Retourne (corps, corps_sûr, erreur).

    Chemin FAIL-CLOSED unique : dupliqué par endpoint, il se serait mis à
    diverger au premier ajout d'exception, et une branche oubliée renverrait
    la requête telle quelle à l'amont.
    """
    try:
        body = json.loads(await request.body())
    except json.JSONDecodeError as exc:
        return None, None, _fail(400, "invalid_request_error", f"corps JSON invalide : {exc}")

    sub_out = state.outgoing()
    try:
        # Traversée synchrone (détection HTTP + SQLite) hors boucle d'événements.
        safe_body = await anyio.to_thread.run_sync(lambda: walk_request(body, sub_out))
    except DetectionUnavailable as exc:
        return None, None, _fail(
            503, "api_error", f"pseudonymisation impossible, requête refusée : {exc}")
    except (VaultUnavailableError, SurrogateCollisionError, ValueError) as exc:
        return None, None, _fail(
            503, "api_error", f"substitution impossible, requête refusée : {exc}")
    # L'annonce est ajoutée APRÈS la substitution : c'est notre texte, il
    # n'a pas à traverser le détecteur, qui y verrait des entités.
    return body, injecter(safe_body, state.policy.reglage("annonce")), None


@app.post("/v1/messages")
async def messages(request: Request):
    state: ProxyState = request.app.state.proxy
    body, safe_body, erreur = await _pseudonymize(state, request)
    if erreur is not None:
        return erreur

    headers = _forward_headers(request)
    streaming = bool(body.get("stream"))

    if not streaming:
        try:
            upstream = await state.client.post(
                "/v1/messages", json=safe_body, headers=headers,
                params=dict(request.query_params),
            )
        except httpx.HTTPError as exc:
            return _fail(502, "api_error", f"amont injoignable : {exc}")

        if upstream.headers.get("content-type", "").startswith("application/json"):
            sub_in = state.incoming()
            try:
                restored, unresolved = walk_response(upstream.json(), sub_in)
            except (ValueError, json.JSONDecodeError) as exc:
                # `walk_response` lève ValueError sur un corps qui n'est pas un
                # objet, justement pour laisser le proxy décider. Sans ce
                # rattrapage, le fail-closed devenait un 500 non structuré.
                return _fail(502, "api_error", f"corps amont inexploitable : {exc}")
            _note_unresolved(state, unresolved)
            return JSONResponse(
                status_code=upstream.status_code,
                content=restored,
                headers=_drop_len(_response_headers(upstream)),
            )
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=_drop_len(_response_headers(upstream)),
        )

    return await _stream(state, safe_body, headers, dict(request.query_params))


def _erreur_restauree(payload: bytes, sub_in, state: ProxyState) -> dict[str, Any]:
    """Événement `error` SSE dont les substituts sont résolus pour l'opérateur.

    Un corps qui n'est pas du JSON d'erreur exploitable est relayé tel quel :
    on ne devine pas sa structure, mais on ne le perd pas non plus.
    """
    texte = payload.decode("utf-8", "replace")
    try:
        corps = json.loads(texte)
    except json.JSONDecodeError:
        corps = None
    if isinstance(corps, dict) and isinstance(corps.get("error"), dict):
        restored, unresolved = walk_response(corps, sub_in)
        _note_unresolved(state, unresolved)
        return {"type": "error", "error": restored["error"]}
    resolu, unresolved = sub_in.to_real(texte)
    _note_unresolved(state, unresolved)
    return {"type": "error", "error": {"type": "api_error", "message": resolu}}


async def _stream(state: ProxyState, safe_body: dict[str, Any], headers: dict[str, str],
                  params: dict[str, str]):
    """Relaie le SSE amont en restaurant les valeurs réelles à la volée."""
    sub_in = state.incoming()

    async def generator():
        rewriter = SSERewriter(sub_in)
        buffer = ""
        try:
            async with state.client.stream(
                "POST", "/v1/messages", json=safe_body, headers=headers, params=params
            ) as upstream:
                if upstream.status_code >= 400:
                    payload = await upstream.aread()
                    logger.error("amont %s : %s", upstream.status_code, payload[:500])
                    # Un message d'erreur amont cite ce qu'il a reçu, donc des
                    # SUBSTITUTS. Le rendre brut donnait à l'opérateur des
                    # erreurs illisibles (« hôte inconnu <fictif> ») là où la
                    # branche non-streamée restaure le même corps.
                    yield encode_sse(_erreur_restauree(payload, sub_in, state))
                    return

                async for chunk in upstream.aiter_text():
                    blocks, buffer = iter_blocks(chunk, buffer)
                    for block in blocks:
                        event = parse_sse_block(block)
                        if event is None:
                            yield (block + "\n\n").encode("utf-8")  # ping, commentaire
                            continue
                        for out_event in rewriter.feed(event):
                            yield encode_sse(out_event)
                # Un `content_block_stop` d'index inconnu laissait du texte
                # accumulé sans jamais l'émettre.
                for out_event in rewriter.close():
                    yield encode_sse(out_event)
        except (httpx.HTTPError, FluxSSEInvalide) as exc:
            logger.error("flux amont interrompu : %s", exc)
            yield encode_sse({
                "type": "error",
                "error": {"type": "api_error", "message": f"flux interrompu : {exc}"},
            })
        except (TypeError, AttributeError, ValueError, KeyError,
                SurrogateCollisionError, VaultUnavailableError) as exc:
            # Un événement amont mal typé tuait la génératrice SANS rien
            # émettre : le client perdait le flux en silence. On remonte une
            # erreur SSE exploitable plutôt qu'une connexion coupée.
            logger.exception("événement SSE amont inexploitable")
            yield encode_sse({
                "type": "error",
                "error": {"type": "api_error",
                          "message": f"événement amont inexploitable : {exc}"},
            })
        finally:
            _note_unresolved(state, rewriter.unresolved)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"cache-control": "no-cache", "connection": "keep-alive"},
    )


def _note_unresolved(state: ProxyState, unresolved: list[str]) -> None:
    """D5 : un substitut inconnu est signalé, jamais deviné."""
    if not unresolved:
        return
    state.unresolved_total += len(unresolved)
    logger.warning(
        "substituts non résolus (le modèle en a inventé — laissés en place) : %s",
        sorted(set(unresolved))[:10],
    )


def _drop_len(headers: dict[str, str]) -> dict[str, str]:
    """Le corps change de taille après restauration : Content-Length recalculé."""
    return {k: v for k, v in headers.items() if k.lower() != "content-length"}


# --------------------------------------------------------------------------- #
# /v1/messages/count_tokens
# --------------------------------------------------------------------------- #


@app.post("/v1/messages/count_tokens")
async def count_tokens(request: Request):
    state: ProxyState = request.app.state.proxy
    _body, safe_body, erreur = await _pseudonymize(state, request)
    if erreur is not None:
        return erreur

    try:
        upstream = await state.client.post(
            "/v1/messages/count_tokens", json=safe_body, headers=_forward_headers(request),
            params=dict(request.query_params),
        )
    except httpx.HTTPError as exc:
        return _fail(502, "api_error", f"amont injoignable : {exc}")

    # La réponse ne contient que des compteurs : rien à restaurer.
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_drop_len(_response_headers(upstream)),
    )


# --------------------------------------------------------------------------- #
# Santé et passthrough
# --------------------------------------------------------------------------- #


@app.get("/healthz")
async def healthz(request: Request):
    state: ProxyState = request.app.state.proxy
    try:
        detector = state.detector.health()
    except DetectionUnavailable as exc:
        return JSONResponse(status_code=503, content={"status": "detector_down", "detail": str(exc)})
    return {
        "status": "ok",
        "scope": state.settings.scope_key,
        "upstream": state.settings.upstream_base,
        "vault_entries": state.vault.count(state.settings.scope_key),
        "unresolved_total": state.unresolved_total,
        "pipeline": dict(state.pseudonymizer.stats),
        "detector": detector,
    }


#: Chemins d'API portant potentiellement du contenu de conversation. Un POST
#: sur l'un d'eux qui n'est PAS explicitement modélisé est REFUSÉ : le laisser
#: transiter enverrait le corps brut à l'amont (`/v1/messages/batches`,
#: `/v1/complete`, une future `/v2/messages`…). Fail-closed (D9).
_MODEL_API_PREFIXES = ("v1/", "v2/", "v3/")
_MUTATING = {"POST", "PUT", "PATCH"}


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def passthrough(path: str, request: Request):
    """Transit tel quel des chemins hors modèle (télémétrie, bootstrap, OAuth).

    Ces chemins ne portent pas de contenu de conversation et restent sous la
    surveillance du harnais d'egress de la Phase 0. Tout chemin d'API modèle
    non modélisé est en revanche refusé, pas transmis.
    """
    state: ProxyState = request.app.state.proxy

    if request.method in _MUTATING and path.startswith(_MODEL_API_PREFIXES):
        return _fail(
            501, "invalid_request_error",
            f"chemin d'API modèle non modélisé par le proxy : /{path}. "
            "La requête est refusée plutôt que transmise sans pseudonymisation "
            "(fail-closed). Ajouter une route dédiée pour le prendre en charge.",
        )

    body = await request.body()
    try:
        upstream = await state.client.request(
            request.method,
            f"/{path}",
            content=body or None,
            headers=_forward_headers(request),
            params=dict(request.query_params),
        )
    except httpx.HTTPError as exc:
        return _fail(502, "api_error", f"amont injoignable : {exc}")
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_drop_len(_response_headers(upstream)),
    )
