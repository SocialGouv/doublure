"""What to do with a destination, decided before connecting to it.

The forward proxy is the only component that sees EVERY destination an agent
opens. That makes its default the most consequential line in the module: an
unknown host is **refused**, because forgetting to list one must not be the
same as allowing it.

`TUNNEL` is not a weaker `INSPECT`, it is a different answer. A host that pins
its certificate breaks under interception, and a destination whose payload we
have no business reading is better relayed blind than decrypted. Naming the two
separately keeps "I chose not to look" distinguishable from "I could not look".
"""
from __future__ import annotations

import enum
import ipaddress


class Verdict(enum.Enum):
    #: Terminer le TLS, lire et réécrire les corps.
    INSPECT = "inspect"
    #: Relayer les octets sans les lire.
    TUNNEL = "tunnel"
    #: Ne pas ouvrir la connexion du tout.
    REFUSE = "refuse"


def _hote_nu(destination: str) -> str:
    """`example.test:8443` désigne le même hôte que `example.test`."""
    hote = destination.strip().lower()
    if hote.startswith("["):  # littéral IPv6, avec ou sans port
        return hote.partition("]")[0].lstrip("[")
    return hote.rsplit(":", 1)[0] if hote.count(":") == 1 else hote


def _est_adresse(valeur: str) -> bool:
    try:
        ipaddress.ip_address(valeur)
        return True
    except ValueError:
        return False


def _couvre(regle: str, hote: str) -> bool:
    """La règle couvre-t-elle cet hôte ?

    Comparé comme un HÔTE, jamais comme une sous-chaîne : `example.test` couvre
    `docs.example.test` mais pas `example.test.attaquant.test`, dont le
    propriétaire n'est pas le même. Une ADRESSE n'a pas de sous-domaine, donc
    elle ne se compare qu'à l'identique — sans quoi `7.0.0.1` couvrirait
    `127.0.0.1`.
    """
    if hote == regle:
        return True
    if _est_adresse(regle) or _est_adresse(hote):
        return False
    return hote.endswith("." + regle)


class ForwardPolicy:
    """Verdict par destination, avec le refus pour défaut."""

    def __init__(self, inspect: list[str], tunnel: list[str]):
        self.inspect = [r.strip().lower() for r in inspect if r.strip()]
        self.tunnel = [r.strip().lower() for r in tunnel if r.strip()]
        if doublons := set(self.inspect) & set(self.tunnel):
            # Se résoudrait en silence par l'ordre de lecture : le mode
            # d'interception d'un hôte serait décidé par un hasard d'écriture.
            raise ValueError(
                "destination déclarée dans les deux listes : "
                + ", ".join(sorted(doublons)))

    @classmethod
    def load(cls, path) -> "ForwardPolicy":
        """Lit `<verbe> <destination>` par ligne.

        Le fichier vit dans le RÉPERTOIRE D'ÉTAT, hors de portée de l'agent :
        chaque ligne OUVRE une destination réseau, `tunnel` comme `inspect`.
        C'est la même décision que pour les domaines ouverts, et pour la même
        raison — si l'agent peut l'écrire, il s'ouvre sa propre sortie.

        Un verbe inconnu est une ERREUR : le traiter comme un commentaire
        transformerait une faute de frappe en destination silencieusement
        absente, donc refusée sans que personne comprenne pourquoi.
        """
        from pathlib import Path

        p = Path(path)
        if not p.exists():
            return cls(inspect=[], tunnel=[])  # rien d'ouvert
        inspect, tunnel = [], []
        for numero, ligne in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            ligne = ligne.strip()
            if not ligne or ligne.startswith("#"):
                continue
            verbe, _, destination = ligne.partition(" ")
            destination = destination.strip()
            if not destination:
                raise ValueError(f"{p}:{numero} — il faut `<verbe> <destination>`")
            if verbe == "inspect":
                inspect.append(destination)
            elif verbe == "tunnel":
                tunnel.append(destination)
            else:
                raise ValueError(
                    f"{p}:{numero} — verbe inconnu {verbe!r} : "
                    f"attendu `inspect` ou `tunnel`")
        return cls(inspect=inspect, tunnel=tunnel)

    def verdict(self, destination: str) -> Verdict:
        hote = _hote_nu(destination)
        candidats = [(len(r), Verdict.INSPECT) for r in self.inspect
                     if _couvre(r, hote)]
        candidats += [(len(r), Verdict.TUNNEL) for r in self.tunnel
                      if _couvre(r, hote)]
        if not candidats:
            return Verdict.REFUSE
        # La règle la PLUS PRÉCISE gagne : c'est ce qui permet d'épargner un
        # hôte qui épingle son certificat sans rouvrir tout son domaine.
        return max(candidats)[1]
