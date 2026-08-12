"""Pseudonymising an MCP body — JSON-RPC in, JSON-RPC out.

JSON-RPC has the shape this project has already been burnt by five times: a
thin envelope that must stay verbatim, wrapped around free-form data where a
KEY carries as much as a value does.

So the rule is the one the walker reached the hard way: **a key is protocol by
its POSITION, never by its name.** `id` at the message level correlates the
response; `id` inside `params` is a customer record. Deriving the answer from
the key name is what let a hostile server forge protection for its own subtree,
four rounds running.

**Accepted leak, stated rather than discovered**: `params.name` stays verbatim.
It is the routing key an MCP server dispatches on, and substituting it breaks
the call silently — the same arbitration as `tools[].name` on the Anthropic
side, and the same reason: it is a naming convention, not a value.

**Deliberate breakage**: everything else under `params` is substituted, URIs
included, even though a remote server cannot resolve a fictional one. A call
that fails is VISIBLE — the agent stumbles and the operator sees it. A value
that leaves is silent. That asymmetry is the whole project, and it is not
suspended because a call is inconvenient.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import json
import re
import zlib
from typing import Callable

from anonproxy.serialisation import dumps_utf8

#: Clés du protocole, au NIVEAU DU MESSAGE uniquement.
_ENVELOPPE = frozenset({"jsonrpc", "id", "method"})
#: …et la FORME que JSON-RPC 2.0 leur impose. Recopier ces clés sans regarder
#: leur valeur suffisait à faire sortir n'importe quoi : un `id` porteur d'un
#: objet ou d'une liste traversait verbatim dans un sens et n'était pas restauré
#: dans l'autre, et c'est l'ÉMETTEUR qui choisissait. Même défaut que la clé de
#: routage voisine, durcie au tour précédent sur (position ET forme) — la règle
#: n'avait pas été portée aux trois autres. `id` accepte une chaîne, un nombre
#: ou `null` ; `jsonrpc` et `method` sont des chaînes.
_FORME_ENVELOPPE = {"jsonrpc": str, "method": str,
                    "id": (str, int, float, type(None))}
#: Clé de routage d'un appel d'outil : verbatim, fuite assumée.
_ROUTAGE = frozenset({"name"})
#: Sous-arbres de données libres d'un message JSON-RPC.
_DONNEES = frozenset({"params", "result", "error"})
#: Ce qui EST du base64 canonique : alphabet standard, longueur multiple de
#: quatre, bourrage correct. Il n'y a PAS de liste de noms de champs — il y en
#: avait une (`blob`, `data`, `content`), et ce nom est écrit par l'amont : il
#: lui suffisait de ranger sa charge sous `payload` ou `attachment` pour que la
#: protection tombe. Même anti-pattern que le type MIME, au même endroit.
#:
#: L'alphabet STANDARD exclut le base64url sans bourrage, donc les parties d'un
#: JWT : une signature ne doit pas être traversée.
_BASE64 = re.compile(
    r"(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
#: Ce qu'un décodeur permissif JETTE avant de décoder. C'est son contrat qui
#: fait foi, pas le nôtre : la protection ne peut pas reposer sur une lecture
#: plus étroite que celle du destinataire.
_HORS_ALPHABET = re.compile(r"[^A-Za-z0-9+/=]")
#: Idem, bourrage compris. Les récepteurs ne lisent PAS la même chose : Python
#: jette les `=` égarés et décode le flux entier, `Buffer.from` de Node s'arrête
#: au premier. Deux lectures, donc, et protéger l'une laisse l'autre ouverte.
_HORS_ALPHABET_NI_BOURRAGE = re.compile(r"[^A-Za-z0-9+/]")
#: PAS de longueur minimale. J'en avais posé une (16 caractères) « parce
#: qu'en dessous ce n'est pas une charge » : `10.0.0.1` s'encode en douze
#: caractères, `srv-42` en huit. Toute IPv4 et tout nom d'hôte court passaient
#: donc intacts — et c'était une RÉGRESSION sur les champs qui étaient déjà
#: décodés sans borne.
#:
#: Troisième garde-fou à échec silencieux en trois heures, tous les miens, tous
#: posés « par prudence » au-dessus d'une décision qui n'en demandait pas. Ce
#: qui les rend inutiles est la même chose qui rend le balayage sûr : le tour
#: est l'IDENTITÉ quand rien n'est détecté.

#: Borne de la charge DÉTENDUE. Le proxy plafonne ce qu'il LIT à 32 Mio ; la
#: décompression, elle, alloue ce que l'amont décide. Même borne, même raison —
#: ce qui ne tient pas en mémoire ne peut pas être pseudonymisé — mais c'est
#: ici qu'elle manquait, et l'entrée n'en dit rien : 199 Kio de zéros gzipés
#: font 200 Mio en sortie, mesurés.
_MAX_CLAIR = 32 * 1024 * 1024

#: Charges encodées lues dans UNE chaîne. Le balayage reprend au reste
#: après chaque charge, donc son coût est le carré de la longueur : huit
#: mille charges collées tenaient le proxy huit secondes. Aucune forme
#: légitime n'en aligne autant dans une seule chaîne.
_MAX_CHARGES = 256


def _decoder(base64_lu: str) -> str | None:
    """Le texte que ces caractères encodent, ou None si ce n'en est pas."""
    try:
        return base64.b64decode(base64_lu, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


class BinaryBody(RuntimeError):
    """Ce corps n'est pas du texte : il ne peut être ni relu ni réécrit."""


def _poser(rendu: dict, cle, valeur) -> None:
    """Écrit une paire, ou REFUSE si la clé est déjà prise.

    Deux clés distinctes qui convergent vers la même après transformation : la
    seconde écrasait la première, et une valeur DISPARAISSAIT du message — dans
    les deux sens. Au retour, c'est ce que le serveur MCP a réellement répondu
    qui n'arrive jamais à l'opérateur, sans exception ni compteur.

    Le walker Anthropic a ce garde ; ce canal-ci ne l'avait pas. Un résidu
    accepté se compte ; une perte de donnée se refuse.
    """
    if cle in rendu:
        raise BinaryBody(
            f"collision de clés après transformation : {cle!r} est déjà "
            "présent dans ce bloc, une valeur serait perdue")
    rendu[cle] = valeur


#: PAS de garde « est-ce que ça ressemble à du texte ? ». J'en avais écrit un —
#: refus sur un octet nul ou plus de 5 % de caractères de contrôle — pour
#: épargner un binaire court qui décoderait par hasard. Il suffisait alors de
#: glisser UN octet nul dans la charge pour supprimer la substitution : la
#: valeur réelle sortait, sans entrée au coffre ni rien à compter.
#:
#: Le commentaire juste au-dessus énonçait pourtant la règle qu'il violait —
#: se tromper vers le binaire laisse sortir en SILENCE, se tromper vers le
#: texte corrompt VISIBLEMENT. Un garde-fou dont l'échec est silencieux et que
#: l'attaquant déclenche à volonté n'est pas un garde-fou.
#:
#: Le décodage UTF-8 reste le seul juge : un vrai binaire échoue dessus dès ses
#: premiers octets. Résidu assumé : un binaire fait uniquement d'octets valides
#: en UTF-8 sera traversé, donc possiblement modifié — et ça se voit.


class JsonRpcTransform:
    """`BodyTransform` pour un canal MCP.

    Les deux sens ne sont pas symétriques et ne doivent jamais l'être : ce qui
    sort est pseudonymisé, ce qui entre est restauré.
    """

    def __init__(self, to_surrogate: Callable[[str], str],
                 to_real: Callable[[str], str]):
        self._sortant = to_surrogate
        self._entrant = to_real

    # ------------------------------------------------------------------ sens

    def outgoing(self, host: str, headers: dict[str, str], body: bytes) -> bytes:
        return self._appliquer(body, self._sortant, headers)

    def incoming(self, host: str, headers: dict[str, str], body: bytes) -> bytes:
        return self._appliquer(body, self._entrant, headers)

    # --------------------------------------------------------------- moteur

    def _appliquer(self, body: bytes, transformer: Callable[[str], str],
                   headers: dict[str, str] | None = None) -> bytes:
        if not body:
            return body
        # Un corps gzipé est du TEXTE compressé. Sans le détendre, il levait
        # `BinaryBody` — que l'échange ne rattrape pas — et la connexion
        # mourait sans 502, sur une réponse parfaitement ordinaire.
        comprime = (headers or {}).get("content-encoding", "").lower() in (
            "gzip", "x-gzip")
        if comprime:
            body = self._detendre(body)
        try:
            rendu = self._appliquer_clair(body, transformer)
        except RecursionError as exc:
            # `json.loads` est itératif en C et avale une profondeur
            # arbitraire ; la traversée, elle, récurse en Python. Douze kilos
            # d'octets — très en dessous de la limite d'entrée — faisaient
            # sauter la pile, et la connexion mourait sans un mot. Même classe
            # que la bombe gzip : une petite entrée, un coût disproportionné.
            raise BinaryBody(
                "JSON trop profond pour être relu sans épuiser la pile") from exc
        return gzip.compress(rendu) if comprime else rendu

    @staticmethod
    def _detendre(body: bytes) -> bytes:
        """Décompresse en BORNANT la sortie.

        `gzip.decompress` alloue ce que l'amont décide : sur du texte répétitif
        un rapport de 1000:1 est banal, donc les 32 Mio que le proxy accepte en
        entrée peuvent en demander des milliers en sortie. Mesuré avant
        correctif : 199 Kio de charge, 400 Mio alloués, et la limite d'entrée
        n'y voyait rien — c'est la seule borne du chemin qui portait sur la
        mauvaise grandeur.
        """
        moteur = zlib.decompressobj(wbits=31)
        try:
            clair = moteur.decompress(body, _MAX_CLAIR)
        except zlib.error as exc:
            raise BinaryBody(f"corps gzip illisible : {exc}") from exc
        if moteur.unconsumed_tail or moteur.unused_data or not moteur.eof:
            # Détendu au-delà de la borne, ou plusieurs membres gzip : dans les
            # deux cas on ne peut pas rendre le corps entier, et en rendre une
            # partie dirait qu'on l'a lu.
            raise BinaryBody(
                f"corps gzip détendu au-delà de {_MAX_CLAIR} octets, ou en "
                "plusieurs membres : il ne peut pas être relu")
        return clair

    def _appliquer_clair(self, body: bytes,
                         transformer: Callable[[str], str]) -> bytes:
        try:
            texte = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            # Sur une destination déclarée À INSPECTER, relayer ce qu'on ne
            # sait pas lire dirait que ça a été lu.
            raise BinaryBody("corps non textuel : il ne peut pas être relu") from exc
        try:
            message = json.loads(texte)
        except (json.JSONDecodeError, ValueError):
            # Un corps tronqué ou un format tiers reste du TEXTE : le protéger
            # entier est le sens sûr, et ça ne tue pas la connexion. Il passe
            # par `_chaine`, pas par le transformateur seul : une charge base64
            # posée dans un corps non-JSON — `log <base64 du réel>` — sortait
            # sinon entière, jamais décodée.
            return self._chaine(texte, transformer).encode("utf-8")
        # UN seul niveau de lot, ce que dit la spec. En descendant plus loin,
        # tout dict interne recevait le traitement d'enveloppe — `id` et
        # `method` verbatim, alors que ce sont des données à cette profondeur.
        if isinstance(message, list):
            rendu = [self._message(m, transformer) for m in message]
        else:
            rendu = self._message(message, transformer)
        return dumps_utf8(rendu)

    def _message(self, noeud, transformer):
        """Niveau MESSAGE : l'enveloppe est du protocole, le reste des données."""
        if not isinstance(noeud, dict):
            return self._libre(noeud, transformer)
        rendu = {}
        for cle, valeur in noeud.items():
            if cle in _ENVELOPPE and isinstance(valeur, _FORME_ENVELOPPE[cle]):
                rendu[cle] = valeur
            elif cle in _DONNEES:
                # Le ROUTAGE ne vit que sous `params` : c'est la requête qui
                # nomme l'outil à appeler. `result` et `error` sont ce que le
                # serveur REND, et un `name` y est une donnée comme une autre.
                rendu[cle] = self._donnees(valeur, transformer,
                                           routage=cle == "params")
            else:
                # La CLÉ passe par le lecteur de charges comme partout ailleurs.
                # Ce niveau-ci était le seul à la recopier verbatim : une clé
                # supplémentaire au niveau message — un serveur en ajoute pour
                # sa télémétrie — sortait telle quelle, et n'était pas restaurée
                # au retour. Quatrième position que les tests ignoraient, dans
                # le même fichier ; le docstring du module dit pourtant qu'une
                # clé est du protocole par sa POSITION, jamais par son nom.
                _poser(rendu, self._chaine(cle, transformer),
                       self._libre(valeur, transformer))
        return rendu

    def _donnees(self, noeud, transformer, *, routage: bool):
        """Premier niveau sous `params`/`result`/`error`.

        La clé de ROUTAGE n'y est du protocole que sous `params`, et seulement
        si sa valeur a la FORME d'un nom d'outil. Exempter les trois surfaces
        indistinctement traitait `result.name` et `error.name` — que le serveur
        ÉCRIT — comme du routage : la clé ET la valeur sortaient verbatim dans
        un sens, et n'étaient pas restaurées dans l'autre, l'opérateur lisant
        alors le substitut. Une valeur non scalaire emportait tout son
        sous-arbre avec elle.

        C'est la règle que le walker a mise huit tours à formuler : une clé de
        protocole est gardée par sa POSITION ou par la FORME de sa valeur,
        jamais recopiée inconditionnellement. Elle n'avait jamais été portée
        sur ce canal.
        """
        if not isinstance(noeud, dict):
            return self._libre(noeud, transformer)
        rendu: dict = {}
        for cle, valeur in noeud.items():
            protege = routage and cle in _ROUTAGE and isinstance(valeur, str)
            # La clé passe par `_chaine`, pas par le transformateur seul :
            # une charge base64 est une charge où qu'elle soit, et la placer en
            # CLÉ suffisait à ce qu'elle traverse verbatim. Le docstring de
            # `_libre` disait déjà « la clé est une valeur comme une autre » ;
            # le code ne le tenait que pour le texte, pas pour ce qu'il encode.
            _poser(rendu, cle if protege else self._chaine(cle, transformer),
                   valeur if protege else self._libre(valeur, transformer))
        return rendu

    @staticmethod
    def _lectures(valeur: str) -> list[tuple[int, str]]:
        """Les textes que les RÉCEPTEURS peuvent tirer de cette chaîne.

        Ce qui décide n'est pas « cette chaîne EST-elle du base64 » mais « que
        décode celui d'en face » — et ils ne décodent pas la même chose. Mesuré :
        Python jette les `=` égarés et lit le flux entier, `Buffer.from` de Node
        s'arrête au premier, le décodeur strict de Go refuse mais rend quand même
        le préfixe déjà décodé à qui ignore son erreur. Protéger UNE lecture
        laisse les autres ouvertes, donc on les rend TOUTES et l'appelant
        substitue dès que l'une d'elles porte une valeur.

        Chaque lecture dit aussi où elle s'arrête dans la chaîne d'origine : la
        suite est du texte, à protéger comme tel plutôt qu'à effacer.

        Trois formulations successives de la même erreur ont été payées ici, et
        c'est la même à chaque fois — un contrat plus ÉTROIT que celui du
        destinataire. On exigeait la canonicité (un bit de bourrage éteignait la
        substitution), puis on ne retirait que les blancs (un caractère invisible
        l'éteignait), puis on exigeait que la chaîne ENTIÈRE ait la forme (quatre
        caractères collés derrière le bourrage l'éteignaient).
        """
        lectures: list[tuple[int, str]] = []
        compact = _HORS_ALPHABET.sub("", valeur)
        lu = _BASE64.match(compact)
        if lu is not None and (clair := _decoder(lu.group())) is not None:
            # Le compactage a supprimé des caractères : les positions ne se
            # correspondent plus, on recompte pour retrouver la fin dans
            # l'original.
            restant, fin = lu.end(), len(valeur)
            for i, c in enumerate(valeur):
                if _HORS_ALPHABET.match(c) is None:
                    restant -= 1
                    if restant == 0:
                        fin = i + 1
                        break
            lectures.append((fin, clair))
            if lu.end() == len(compact):
                return lectures  # la première a tout couvert : rien à ajouter
        # La lecture la plus LARGE sert dès que la première ne couvre pas tout,
        # et le déclencheur a déjà été trop étroit une fois. Je l'avais restreint
        # au `=` posé hors bourrage final — le seul cas connu alors — et le
        # base64 SANS bourrage passait donc à travers les deux : `_BASE64` exige
        # un `=` en fin, la première lecture s'arrête un quantum trop tôt et rend
        # `db-01.acme.interna`, où il n'y a rien à substituer, tandis que
        # `Buffer.from` de Node complète le bourrage et lit la valeur entière.
        # Le déclencheur est donc la NON-COUVERTURE, pas la liste des raisons
        # qui la produisent. Ici la chaîne est une charge d'un bout à l'autre,
        # donc pas de suite.
        noyau = _HORS_ALPHABET_NI_BOURRAGE.sub("", valeur)
        if len(noyau) % 4 == 1:
            noyau = noyau[:-1]
        if noyau and (clair := _decoder(noyau + "=" * (-len(noyau) % 4))) is not None:
            lectures.append((len(valeur), clair))
        return lectures

    def _chaine(self, valeur: str, transformer) -> str:
        """Une chaîne, décodée d'abord si un récepteur peut en tirer du texte.

        Appelée pour TOUTE chaîne, feuille de dict comme élément de liste. La
        traversée des charges ne vivait que dans la branche dict : une charge
        rangée dans une LISTE — `{"blobs": ["<base64>"]}`, la forme la plus
        banale d'un lot de ressources MCP — sortait en clair, à toute
        profondeur.

        Une lecture qui ne porte RIEN ne doit pas empêcher la suivante, ni
        surtout empêcher la protection du TEXTE : `10.1.2.3` se réduit à quatre
        caractères qui se décodent, et court-circuiter là-dessus aurait laissé
        l'adresse sortir en clair.

        Ce qui SUIT une charge est relu comme une chaîne, pas seulement
        transformé comme du texte : une même chaîne peut porter PLUSIEURS
        charges collées, et se contenter du texte protégeait la première en
        laissant partir toutes les suivantes. Cinquième position que les tests
        ignoraient — après la valeur, la liste, la clé et le niveau message —
        et la seule qui vive à l'intérieur d'une chaîne.
        """
        morceaux: list[str] = []
        reste = valeur
        substitue = False
        for _ in range(_MAX_CHARGES):
            if not reste:
                break
            lectures = self._lectures(reste)
            for fin, clair in lectures:
                rendu = transformer(clair)
                if rendu == clair:
                    continue
                morceaux.append(
                    base64.b64encode(rendu.encode("utf-8")).decode("ascii"))
                reste, substitue = reste[fin:], True
                break
            else:
                if not lectures:
                    # Aucune lecture ICI ne veut pas dire aucune lecture PLUS
                    # LOIN. Une charge d'un ou deux octets (`aGk=`, `YQ==`)
                    # n'a que trois caractères avant son bourrage, donc le
                    # motif échoue à l'origine — et tout ce qui suivait était
                    # abandonné au texte, charge du réel comprise. On avance
                    # jusqu'au prochain candidat ; s'il commence ici, on passe
                    # au-delà, sinon la boucle ne progresserait pas.
                    suivant = _BASE64.search(reste)
                    if suivant is None:
                        morceaux.append(transformer(reste))
                        reste = ""
                        break
                    coupe = suivant.start() or suivant.end()
                    morceaux.append(transformer(reste[:coupe]))
                    reste = reste[coupe:]
                    continue
                # Cette charge-ci ne porte rien, la SUIVANTE peut en porter :
                # on avance au lieu de s'arrêter. S'arrêter protégeait la
                # première charge d'une chaîne et laissait partir toutes les
                # autres — encodées, donc sans rien en clair à compter.
                fin = lectures[0][0]
                morceaux.append(transformer(reste[:fin]))
                reste = reste[fin:]
        else:
            # Le nombre de charges d'une chaîne est borné, sinon le balayage
            # coûte le carré de sa longueur : mesuré, huit mille charges
            # collées tiennent le proxy huit secondes. Refuser bruyamment vaut
            # mieux que relayer sans avoir lu.
            raise BinaryBody(
                f"plus de {_MAX_CHARGES} charges encodées dans une seule "
                "chaîne : forme illégitime, relayer sans l'avoir lue serait "
                "un fail-open")
        # Rien n'a été substitué : la chaîne est du TEXTE. C'est là que tient
        # l'IDENTITÉ — un jeton opaque n'y rencontre rien à substituer et
        # ressort tel quel, bourrage non canonique compris.
        return "".join(morceaux) if substitue else transformer(valeur)

    def _libre(self, noeud, transformer):
        """Données libres : la clé est une valeur comme une autre."""
        if isinstance(noeud, dict):
            rendu: dict = {}
            for c, v in noeud.items():
                _poser(rendu, self._chaine(c, transformer),
                       self._libre(v, transformer))
            return rendu
        if isinstance(noeud, list):
            return [self._libre(v, transformer) for v in noeud]
        if isinstance(noeud, str):
            return self._chaine(noeud, transformer)
        # Les nombres, booléens et null ne portent pas d'identifiant : les
        # traverser en texte les transformerait en chaînes et casserait le
        # schéma attendu par le serveur.
        return noeud
