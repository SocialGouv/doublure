"""Politique de confidentialité — fermée par défaut, ouverte par l'opérateur.

Le système anonymise TOUT ce qu'il détecte. L'opérateur peut ensuite décider de
révéler, à trois granularités et sur trois portées.

Granularités, de la plus précise à la plus large :

    valeur   « CETTE date-là »                    empreinte HMAC
    type     « les dates en général »             DATE_TIME, HOSTNAME…
    classe   « toutes les données personnelles »  pii, infra…

Portées, chacune servant de défaut à la suivante (réponse §3.1 — c'est la même
hiérarchie que celle du déterminisme, pas une seconde à maintenir) :

    global  →  projet  →  session

La plus précise l'emporte, et à granularité égale la portée la plus proche
l'emporte. En l'absence de toute règle : ANONYMISER.

## Deux invariants, et ils ne sont pas symétriques

**Un SECRET ne se révèle jamais.** D4 : un secret est une référence dérivée,
jamais stockée, donc jamais restaurable. Une règle qui prétendrait le révéler
est REFUSÉE à l'écriture, pas ignorée à la lecture.

**« Révéler » est la seule décision qui puisse faire sortir une valeur.**
« Anonymiser » est gratuit et réversible ; révéler ne l'est pas — révoquer la
règle plus tard ne rappelle pas ce qui est déjà parti. C'est pourquoi chaque
révélation est TRACÉE, et pourquoi le défaut ne peut pas être autre chose.

## Ce que le fichier de politique contient — et ne contient pas

Aucune valeur réelle. Une décision par valeur est indexée par une empreinte
HMAC dérivée de la clé maître : le fichier peut être lu, versionné ou partagé
sans rien révéler. L'opérateur, lui, voit les valeurs en clair au moment de
l'arbitrage, parce que la file d'attente porte le SUBSTITUT et que le coffre
sait le résoudre.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from enum import Enum
from pathlib import Path

from .modes import (
    ARBITRAGE_BLOQUANT, DELAI_ARBITRAGE, ENV, MODE_DEFAUT, MODES, REGLAGES,
    ReglageInvalide, defauts_du_mode, valide,
)

#: Période de relecture de la politique pendant une attente d'arbitrage.
_PERIODE_SONDAGE = 0.25

logger = logging.getLogger("anonproxy.policy")


class Decision(str, Enum):
    ANONYMISER = "anonymiser"
    REVELER = "reveler"


class PolitiqueInvalide(ValueError):
    """Règle refusée : elle violerait un invariant verrouillé."""


#: Classes dont aucune valeur ne peut être révélée (D4).
CLASSES_NON_REVELABLES = frozenset({"secret"})

#: Portées, de la plus lointaine à la plus proche. L'ordre EST la résolution.
PORTEES = ("global", "projet", "session")

#: Granularités, de la plus large à la plus précise. L'ordre EST la résolution.
GRANULARITES = ("classe", "type", "valeur")


def _fichier_de_portee(racine: Path, portee: str, scope_key: str,
                       session: str | None) -> Path:
    """Un fichier par portée, et deux portées distinctes n'écrivent JAMAIS le
    même fichier.

    **Substituer des caractères ne peut pas être injectif** : plusieurs entrées
    tombent sur la même sortie, et chaque collision fait traverser une décision
    « révéler » d'une portée à une autre. La normalisation d'origine en
    produisait trois — `proj:client` et `proj-client` (`:` → `-`), `team/prod`
    et `team_prod` (`/` → `_`), et les mêmes pour un identifiant de session. Le
    séparateur `-session-` que j'avais ajouté pour séparer les sessions en
    créait une quatrième, pire : le PROJET `acme-session-prod` et la SESSION
    `prod` du projet `acme` — une règle de projet lue par la session d'un
    autre, à travers la portée ET le scope_key.

    D'où : la partie lisible reste pour l'opérateur qui inspecte le
    répertoire, mais ce qui DÉCIDE est l'empreinte du tuple exact. Une
    empreinte ne dépend d'aucun schéma d'échappement — c'est-à-dire d'aucune
    règle que je puisse écrire de travers une quatrième fois.

    Prix ASSUMÉ : les fichiers écrits sous l'ancien nommage ne sont plus lus.
    Une règle perdue retombe sur « anonymiser », jamais sur « révéler » — le
    sens sûr. Les décisions de révélation déjà prises sont à reprendre.
    """
    if portee == "global":
        return racine / "global.json"
    # La SESSION n'entre que dans la portée session. L'avoir mise partout
    # fragmentait la portée PROJET par session : une règle de projet cessait de
    # s'appliquer dès que `ANONPROXY_SESSION` changeait — c'est-à-dire à chaque
    # session, ce qui est sa raison d'être — et « projet sert de défaut à
    # session » ne voulait plus rien dire.
    champs = (portee, scope_key) if portee != "session" else \
        (portee, scope_key, session or "")
    # Chaque champ préfixé par sa LONGUEUR. Un séparateur seul n'est pas plus
    # injectif qu'une substitution de caractères : il suffit que le séparateur
    # apparaisse dans les données. `scope_key="\x1f"` et `session="\x1f"`
    # donnaient la même chaîne, donc le même fichier, donc une révélation qui
    # traverse — la classe même que ce nommage devait fermer, une couche plus
    # bas. Les deux valeurs viennent de variables d'environnement, sans filtre.
    #
    # La longueur se compte en OCTETS, sur la forme même qui est hachée. En
    # caractères, elle divergeait du Go — qui compte des octets — dès qu'un
    # accent entrait dans la clé de portée : `projet-café` vaut 11 d'un côté et
    # 12 de l'autre, donc deux empreintes, donc deux fichiers, donc l'arbitrage
    # de l'opérateur invisible au moteur. `surrogateescape` est l'inverse exact
    # de la lecture d'`os.environ` : on retrouve les octets que le système a
    # donnés, ceux-là mêmes que le Go tient dans sa chaîne.
    octets = [c.encode("utf-8", "surrogateescape") for c in champs]
    exact = b"".join(b"%d:%s" % (len(o), o) for o in octets)
    empreinte = hashlib.sha256(exact).hexdigest()[:16]
    lisible = re.sub(r"[^A-Za-z0-9_.-]", "-", scope_key)[:40].strip("-.") or "portee"
    if portee == "session":
        lisible = f"{lisible}-session"
    return racine / f"{lisible}-{empreinte}.json"


class Policy:
    """Politique résolue sur trois portées, fermée par défaut."""

    def __init__(self, racine: Path, master_key: str, scope_key: str,
                 session: str | None = None):
        self.racine = Path(racine)
        self.scope_key = scope_key
        self.session = session
        # Sel de domaine : l'empreinte d'une politique ne doit pas coïncider
        # avec un index du coffre, qui dérive de la même clé maître.
        self._sel = hmac.new(master_key.encode("utf-8"), b"anonproxy-policy-v1",
                             hashlib.sha256).digest()
        self._lock = threading.RLock()
        self._fichiers = {
            p: _fichier_de_portee(self.racine, p, scope_key, session)
            for p in PORTEES
        }
        self._file_attente = self.racine / "en-attente.jsonl"
        #: Réponses valables pour le MESSAGE en cours, et pour lui seul.
        #:
        #: Ce n'est PAS une quatrième portée : une portée est une règle qui
        #: survit, et une révélation qui survit à ce pour quoi elle a été
        #: accordée est une révélation HÉRITÉE — ce que la philosophie du projet
        #: interdit. C'est la réponse à la question courante, et elle meurt avec
        #: elle. Elle n'entre donc pas non plus dans le nommage des fichiers de
        #: portée, où Python et Go ont divergé deux fois (tours 13 et 14).
        self._reponses = self.racine / "reponses-message.jsonl"
        self._vu: set[str] = set()
        #: portée → ((mtime, taille), contenu). Voir `_charge`.
        self._cache: dict[str, tuple[tuple[int, int] | None, dict]] = {}

    # -- empreintes --------------------------------------------------------- #

    def empreinte(self, etype: str, valeur: str) -> str:
        """Identifie une valeur SANS la contenir.

        Le type entre dans l'empreinte : la même chaîne vue comme HOSTNAME ou
        comme FILE_PATH n'est pas la même décision.
        """
        # `surrogatepass` : un JSON parfaitement valide peut porter une
        # demi-paire de substitution (`"\ud800"`), que `json.loads` accepte
        # et qu'UTF-8 refuse. L'encodage levait alors à travers `decide`
        # jusqu'à `substitute_value`, donc un 500 non structuré là où le
        # contrat promet un refus. Une empreinte n'a pas à être du texte
        # valide : elle a à être STABLE et injective.
        msg = f"{etype}\x1f{valeur}".encode("utf-8", errors="surrogatepass")
        return hmac.new(self._sel, msg, hashlib.sha256).hexdigest()[:32]

    # -- lecture ------------------------------------------------------------ #

    def _charge(self, portee: str) -> dict:
        """Contenu d'une couche, relu seulement s'il a changé.

        La politique est consultée pour CHAQUE valeur détectée : relire trois
        fichiers à chaque fois est du gaspillage. L'empreinte de fraîcheur est
        (mtime, taille), si bien que retirer une règle la referme au prochain
        appel — pas au prochain redémarrage.
        """
        chemin = self._fichiers[portee]
        try:
            etat = chemin.stat()
            fraicheur = (etat.st_mtime_ns, etat.st_size)
        except OSError:
            fraicheur = None
        cache = self._cache.get(portee)
        if cache is not None and cache[0] == fraicheur:
            return cache[1]
        contenu = self._relit(chemin)
        self._cache[portee] = (fraicheur, contenu)
        return contenu

    @staticmethod
    def _relit(chemin: Path) -> dict:
        try:
            brut = json.loads(chemin.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            # Une politique illisible n'ouvre RIEN : on retombe sur le défaut,
            # qui est d'anonymiser. Mais l'échec doit se voir.
            logger.error("politique %s illisible (%s) — défaut : anonymiser",
                         chemin, exc)
            return {}
        return brut if isinstance(brut, dict) else {}

    def decide(self, etype: str, klass: str,
               valeur: str) -> tuple[Decision, str | None]:
        """Décision applicable, et la règle qui l'a prise (None = défaut).

        La règle est cherchée de la plus PRÉCISE à la plus large, et pour
        chacune de la portée la plus PROCHE à la plus lointaine.
        """
        if klass in CLASSES_NON_REVELABLES:
            return Decision.ANONYMISER, "invariant:D4"
        cles = {
            "valeur": self.empreinte(etype, valeur),
            "type": etype,
            "classe": klass,
        }
        # La réponse au MESSAGE en cours est ce qu'il y a de plus proche : elle
        # l'emporte sur toute règle, y compris de session. Elle est cherchée
        # APRÈS D4, jamais avant : un secret ne se révèle pas, même pour un seul
        # message, et cet ordre est ce qui le garantit.
        for granularite in reversed(GRANULARITES):
            brut = self._reponses_du_message().get(f"{granularite}:{cles[granularite]}")
            if brut is not None:
                try:
                    return Decision(brut), f"message:{granularite}"
                except ValueError:
                    logger.error("décision inconnue %r dans une réponse de "
                                 "message — ignorée", brut)
        couches = {p: self._charge(p) for p in PORTEES}
        for granularite in reversed(GRANULARITES):
            for portee in reversed(PORTEES):
                regles = couches[portee].get(granularite) or {}
                brut = regles.get(cles[granularite])
                if brut is None:
                    continue
                try:
                    return Decision(brut), f"{portee}:{granularite}"
                except ValueError:
                    logger.error("décision inconnue %r dans %s/%s — ignorée",
                                 brut, portee, granularite)
        return Decision.ANONYMISER, None

    # -- écriture ----------------------------------------------------------- #

    def definir(self, portee: str, granularite: str, cle: str,
                decision: Decision) -> Path:
        if portee not in PORTEES:
            raise PolitiqueInvalide(f"portée inconnue : {portee!r} (parmi {PORTEES})")
        if granularite not in GRANULARITES:
            raise PolitiqueInvalide(
                f"granularité inconnue : {granularite!r} (parmi {GRANULARITES})")
        if decision is Decision.REVELER and granularite == "classe" \
                and cle in CLASSES_NON_REVELABLES:
            raise PolitiqueInvalide(
                f"la classe {cle!r} n'est jamais révélable (D4 : un secret est "
                "une référence dérivée, il n'est pas restaurable)")
        chemin = self._fichiers[portee]
        with self._lock:
            contenu = self._charge(portee)
            contenu.setdefault(granularite, {})[cle] = decision.value
            chemin.parent.mkdir(parents=True, exist_ok=True)
            chemin.write_text(json.dumps(contenu, indent=2, ensure_ascii=False,
                                         sort_keys=True) + "\n",
                              encoding="utf-8")
            os.chmod(chemin, 0o600)
            # Invalidé APRÈS l'écriture : se fier à la seule empreinte
            # (mtime, taille) laisserait passer une réécriture de même taille
            # sur un système de fichiers à faible résolution temporelle.
            self._cache.pop(portee, None)
        if decision is Decision.REVELER:
            # La seule décision qui puisse faire sortir une valeur : elle est
            # tracée, et sa révocation ultérieure ne rappellera rien.
            logger.warning("RÉVÉLATION autorisée — %s/%s %s (portée %s)",
                           granularite, cle, decision.value, portee)
        return chemin

    def retirer(self, portee: str, granularite: str, cle: str) -> bool:
        # `definir` valide sa portée, pas `retirer` : une portée inconnue y
        # faisait un `KeyError` nu, là où toutes les autres écritures rendent
        # un refus nommé.
        if portee not in PORTEES:
            raise PolitiqueInvalide(f"portée inconnue : {portee!r} (parmi {PORTEES})")
        with self._lock:
            contenu = self._charge(portee)
            if cle not in (contenu.get(granularite) or {}):
                return False
            del contenu[granularite][cle]
            self._fichiers[portee].write_text(
                json.dumps(contenu, indent=2, ensure_ascii=False,
                           sort_keys=True) + "\n", encoding="utf-8")
            self._cache.pop(portee, None)
            return True

    # -- file d'arbitrage --------------------------------------------------- #

    def en_attente(self, etype: str, klass: str, valeur: str,
                   substitut: str) -> None:
        """Consigne une question SANS bloquer et SANS rien révéler.

        Le défaut ayant déjà anonymisé la valeur, la question peut attendre.
        L'entrée ne porte que le SUBSTITUT : c'est le coffre, et lui seul, qui
        sait remonter à la valeur réelle au moment de l'arbitrage.
        """
        empreinte = self.empreinte(etype, valeur)
        with self._lock:
            if empreinte in self._vu:
                return
            self._vu.add(empreinte)
            entree = {
                "empreinte": empreinte, "type": etype, "classe": klass,
                "substitut": substitut, "portee": self.scope_key,
                "vu_le": round(time.time(), 3),
            }
            try:
                neuf = not self._file_attente.exists()
                if neuf:
                    self._file_attente.parent.mkdir(parents=True, exist_ok=True)
                with self._file_attente.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entree, ensure_ascii=False) + "\n")
                if neuf:
                    # Les permissions se posent à la CRÉATION : les reposer à
                    # chaque ajout coûtait un appel système par valeur détectée.
                    os.chmod(self._file_attente, 0o600)
            except OSError as exc:
                logger.error("file d'arbitrage inaccessible (%s) : %s",
                             self._file_attente, exc)

    # -- réponses valables pour un seul MESSAGE ----------------------------- #

    def debut_message(self) -> None:
        """Ouvre un message : ce qui restait d'un précédent est JETÉ.

        Vider à l'ouverture, et pas seulement à la fermeture, est ce qui ferme
        le seul trou de ce dessin : une réponse écrite APRÈS la fin du message
        qu'elle visait s'appliquerait sinon au suivant, c'est-à-dire à des
        valeurs que l'opérateur n'a jamais vues. Jeter est la direction sûre —
        une réponse perdue laisse la valeur anonymisée, jamais l'inverse.
        """
        with self._lock:
            self._reponses.unlink(missing_ok=True)

    def repondre_pour_le_message(self, granularite: str, cle: str,
                                 decision: "Decision") -> None:
        """Réponse à la question courante, valable pour ce message seulement.

        La granularité est la même que pour une règle — une valeur, un type,
        une classe — parce que c'est le même arbitrage, à une portée près :
        l'opérateur qui voit passer trente dates en tranche trente d'un coup.
        """
        if granularite not in GRANULARITES:
            raise PolitiqueInvalide(
                f"granularité inconnue : {granularite!r} (parmi {GRANULARITES})")
        with self._lock:
            self._reponses.parent.mkdir(parents=True, exist_ok=True)
            neuf = not self._reponses.exists()
            with self._reponses.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"granularite": granularite, "cle": cle,
                                     "decision": Decision(decision).value},
                                    ensure_ascii=False) + "\n")
            if neuf:
                os.chmod(self._reponses, 0o600)
        if Decision(decision) is Decision.REVELER:
            # Tracé comme toute révélation : c'est la seule décision qui laisse
            # sortir une valeur, et sa révocation ne rappelle rien.
            logger.warning(
                "RÉVÉLATION autorisée pour CE MESSAGE — %s/%s (elle meurt avec lui)",
                granularite, cle)

    def _reponses_du_message(self) -> dict[str, str]:
        """Les réponses en vigueur, relues à chaque fois.

        Relues et non mises en cache : celui qui répond est un AUTRE processus,
        et une réponse vue une seconde trop tard est une valeur substituée pour
        rien — alors qu'une réponse manquée dans l'autre sens serait une valeur
        révélée sans qu'on l'ait demandé.
        """
        try:
            lignes = self._reponses.read_text(encoding="utf-8").splitlines()
        except (FileNotFoundError, OSError):
            return {}
        rendu: dict[str, str] = {}
        for ligne in lignes:
            if not ligne.strip():
                continue
            try:
                e = json.loads(ligne)
                rendu[f"{e['granularite']}:{e['cle']}"] = e["decision"]
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        return rendu

    def attendre_decision(self, etype: str, klass: str,
                          valeur: str) -> "Decision":
        """Mode CONSCIENCIEUX : bloque jusqu'à ce que l'opérateur tranche.

        La requête attend, c'est le principe du mode — rien de nouveau ne part
        sans qu'un humain l'ait vu. À l'échéance, on ANONYMISE : un délai
        dépassé ne doit jamais valoir un consentement.

        L'attente se fait par relecture du fichier, pas par notification : le
        gestionnaire de configuration est un autre PROCESSUS, souvent un autre
        terminal, et un verrou partagé entre les deux serait une source de
        blocage bien pire que ce sondage.
        """
        delai = self.reglage(DELAI_ARBITRAGE)
        if not delai:
            return Decision.ANONYMISER
        echeance = time.monotonic() + float(delai)
        while time.monotonic() < echeance:
            decision, source = self.decide(etype, klass, valeur)
            if source is not None:
                return decision
            time.sleep(_PERIODE_SONDAGE)
        logger.warning(
            "arbitrage non rendu en %ss pour un %s : la valeur reste anonymisée",
            delai, etype)
        return Decision.ANONYMISER

    def questions(self) -> list[dict]:
        """Questions en attente, dédoublonnées, les plus anciennes d'abord."""
        try:
            lignes = self._file_attente.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        vues, sorties = set(), []
        for ligne in lignes:
            if not ligne.strip():
                continue
            try:
                e = json.loads(ligne)
            except json.JSONDecodeError:
                continue
            if e.get("empreinte") in vues:
                continue
            vues.add(e.get("empreinte"))
            # Une question déjà tranchée depuis n'a plus lieu d'être posée.
            if self._deja_tranchee(e):
                continue
            sorties.append(e)
        return sorties

    def _deja_tranchee(self, entree: dict) -> bool:
        couches = {p: self._charge(p) for p in PORTEES}
        for portee in PORTEES:
            for granularite, cle in (("valeur", entree.get("empreinte")),
                                     ("type", entree.get("type")),
                                     ("classe", entree.get("classe"))):
                if cle in (couches[portee].get(granularite) or {}):
                    return True
        return False

    def resolue(self) -> dict:
        """Vue à plat de la politique, pour le gestionnaire de configuration."""
        return {portee: self._charge(portee) for portee in PORTEES}

    # -- réglages et modes -------------------------------------------------- #
    #
    # Les réglages vivent dans les MÊMES fichiers que les règles, et se
    # résolvent par la MÊME hiérarchie de portées. C'est délibéré : une
    # seconde hiérarchie serait une seconde chose à maintenir, et elles
    # divergeraient.

    def mode(self) -> str:
        """Mode en vigueur : le plus proche l'emporte, l'env prime."""
        if (forcee := os.environ.get("ANONPROXY_MODE")):
            if forcee not in MODES:
                raise ReglageInvalide(
                    f"ANONPROXY_MODE={forcee!r} inconnu "
                    f"(parmi {', '.join(sorted(MODES))})")
            return forcee
        for portee in reversed(PORTEES):
            nomme = (self._charge(portee).get("reglages") or {}).get("mode")
            if nomme in MODES:
                return nomme
            if nomme is not None:
                logger.error("mode inconnu %r dans %s — ignoré", nomme, portee)
        return MODE_DEFAUT

    def reglage(self, nom: str):
        """Valeur d'un réglage : défaut du mode → portées → variable d'env.

        L'environnement gagne toujours : c'est le levier de dépannage, il doit
        primer sur un fichier qu'on ne pense pas à relire.
        """
        if nom not in REGLAGES:
            raise ReglageInvalide(f"réglage inconnu : {nom!r}")
        if (brut := os.environ.get(ENV[nom])):
            return valide(nom, brut)
        for portee in reversed(PORTEES):
            brut = (self._charge(portee).get("reglages") or {}).get(nom)
            if brut is None:
                continue
            try:
                return valide(nom, brut)
            except ReglageInvalide as exc:
                logger.error("%s dans %s — ignoré (%s)", nom, portee, exc)
        return defauts_du_mode(self.mode())[nom]

    def definir_reglage(self, portee: str, nom: str, valeur) -> Path:
        if portee not in PORTEES:
            raise ReglageInvalide(f"portée inconnue : {portee!r}")
        # `mode` n'est pas un réglage comme les autres : il en pose plusieurs.
        normalisee = valeur if nom == "mode" else valide(nom, valeur)
        if nom == "mode" and valeur not in MODES:
            raise ReglageInvalide(
                f"mode inconnu : {valeur!r} (parmi {', '.join(sorted(MODES))})")
        chemin = self._fichiers[portee]
        with self._lock:
            contenu = self._charge(portee)
            contenu.setdefault("reglages", {})[nom] = normalisee
            chemin.parent.mkdir(parents=True, exist_ok=True)
            chemin.write_text(json.dumps(contenu, indent=2, ensure_ascii=False,
                                         sort_keys=True) + "\n",
                              encoding="utf-8")
            os.chmod(chemin, 0o600)
            self._cache.pop(portee, None)
        return chemin

    def reglages_resolus(self) -> dict:
        """Ce qui s'applique réellement, avec le mode qui l'a posé."""
        return {"mode": self.mode(),
                **{nom: self.reglage(nom) for nom in REGLAGES}}
