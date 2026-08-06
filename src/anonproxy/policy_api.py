"""API locale d'arbitrage — la surface de contrôle, jamais un point d'application.

Elle sert une interface (extension VSCode/VSCodium, TUI, script) qui montre à
l'opérateur ce qui a été anonymisé et lui permet de trancher. Elle n'applique
rien : la protection est dans le proxy, et **désinstaller l'interface ne doit
rien ouvrir**. C'est le test de conception à repasser à chaque ajout ici.

## Pourquoi une SOCKET UNIX et pas un port local

Cette API affiche les valeurs RÉELLES — c'est sa raison d'être, on ne peut pas
arbitrer à l'aveugle. Or l'agent tourne sur la même machine, et le hook laisse
passer le loopback :

    autorisé   curl -s http://127.0.0.1:8090/…
    REFUSÉ     curl -s --unix-socket /…/api.sock http://x/…

Un port TCP aurait donc rouvert exactement la mitigation construite contre le
gap « coffre local, même utilisateur » (§3.5) : l'agent aurait lu le coffre par
HTTP au lieu de lire le fichier. La socket ferme les deux — le drapeau est
refusé, et le chemin vit dans le répertoire d'état, déjà couvert par les motifs
de protection du coffre.

Prix assumé, et il est réel : un navigateur ne sait pas parler à une socket
Unix. L'idée d'une petite page servie localement et ouverte dans l'IDE tombe
avec ce choix — l'interface doit être un vrai client (Node sait le faire
nativement, `http.request({socketPath})`).

## Ce que la socket ne protège PAS

Un processus du MÊME utilisateur peut s'y connecter, comme il peut lire la clé
maître. C'est le gap assumé §3.5, inchangé — ni aggravé, ni corrigé. Ajouter un
jeton dans un fichier lisible par le même utilisateur serait du théâtre.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .config import Settings, read_master_key
from .modes import MODES, REGLAGES, ReglageInvalide, defauts_du_mode
from .policy import GRANULARITES, PORTEES, Decision, PolitiqueInvalide, Policy
from .vault import Vault

logger = logging.getLogger("anonproxy.policy_api")


class Etat:
    """Objets vivants de l'API (un par processus)."""

    def __init__(self, settings: Settings):
        self.settings = settings
        master = read_master_key(settings.master_key_file)
        self.policy = Policy(racine=settings.policy_dir, master_key=master,
                             scope_key=settings.scope_key,
                             session=settings.session_id)
        self.vault = Vault(settings.vault_path, master_key=master)

    def questions(self) -> list[dict]:
        """Questions en attente, AVEC la valeur réelle.

        La file ne porte que le substitut : c'est le coffre qui remonte à la
        valeur. L'interface a donc besoin de la clé, comme la CLI — et c'est
        pour ça que cette API ne s'expose pas sur un port.
        """
        vue = self.vault.view(self.settings.scope_key)
        return [
            {**q, "valeur": vue.get(q["substitut"])}
            for q in self.policy.questions()
        ]


app = FastAPI(title="anonproxy — arbitrage")


def _etat() -> Etat:
    etat = getattr(app.state, "anon", None)
    if etat is None:
        etat = Etat(Settings.from_env())
        app.state.anon = etat
    return etat


@app.get("/sante")
def sante():
    etat = _etat()
    return {
        "statut": "ok",
        "portee": etat.settings.scope_key,
        "session": etat.settings.session_id,
        "reglages": etat.policy.reglages_resolus(),
        "modes": {nom: defauts_du_mode(nom) for nom in MODES},
        "questions": len(etat.policy.questions()),
        "coffre": etat.vault.count(etat.settings.scope_key),
    }


@app.get("/questions")
def questions():
    return {"questions": _etat().questions()}


@app.get("/regles")
def regles():
    return {"portees": PORTEES, "granularites": GRANULARITES,
            "regles": _etat().policy.resolue()}


class Arbitrage(BaseModel):
    #: `valeur` | `type` | `classe`
    granularite: str
    #: empreinte, nom de type, ou nom de classe — selon la granularité
    cle: str
    #: `anonymiser` | `reveler`
    decision: str
    portee: str = "projet"


@app.post("/arbitrer")
def arbitrer(demande: Arbitrage):
    etat = _etat()
    try:
        decision = Decision(demande.decision)
    except ValueError:
        raise HTTPException(422, f"décision inconnue : {demande.decision!r}") from None
    try:
        chemin = etat.policy.definir(demande.portee, demande.granularite,
                                     demande.cle, decision)
    except PolitiqueInvalide as exc:
        # Un refus d'invariant n'est pas une erreur de l'appelant à corriger :
        # c'est la règle. On le dit tel quel, il sera affiché à l'opérateur.
        raise HTTPException(409, str(exc)) from None
    return {"ecrit": str(chemin), "decision": decision.value,
            "avertissement": ("cette valeur SORT désormais en clair ; révoquer "
                              "la règle ne rappellera pas ce qui est déjà parti")
            if decision is Decision.REVELER else None}


class Reglage(BaseModel):
    #: un nom de `REGLAGES`, ou `mode`
    nom: str
    valeur: str
    portee: str = "projet"


@app.post("/reglages")
def reglages(demande: Reglage):
    etat = _etat()
    if demande.nom not in (*REGLAGES, "mode"):
        raise HTTPException(422, f"réglage inconnu : {demande.nom!r}")
    try:
        chemin = etat.policy.definir_reglage(demande.portee, demande.nom,
                                             demande.valeur)
    except ReglageInvalide as exc:
        raise HTTPException(422, str(exc)) from None
    return {"ecrit": str(chemin), "reglages": etat.policy.reglages_resolus()}


def chemin_socket(settings: Settings | None = None) -> Path:
    reglages_ = settings or Settings.from_env()
    return Path(os.environ.get("ANONPROXY_API_SOCKET",
                               reglages_.policy_dir.parent / "arbitrage.sock"))
