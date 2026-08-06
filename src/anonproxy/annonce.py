"""Annoncer — ou non — au modèle qu'une couche de pseudonymisation existe.

Le choix est celui de l'opérateur, et les deux options ont un vrai coût.

**Silencieux** (défaut). Le modèle ignore tout de la couche. Anthropic n'en
apprend rien non plus — c'est le réglage le plus fermé. Prix : devant une
incohérence introduite par la substitution, le modèle ne peut que DEVINER. On
l'a mesuré en session réelle — l'inventaire annonçait un sous-réseau
`10.1.2.0/24`, les hôtes sortaient dans un réseau fictif, et le modèle a
conclu que l'inventaire se contredisait. Il avait raison sur ce qu'il voyait,
et tort sur la réalité, sans aucun moyen de le savoir.

**Annoncé**. Le modèle sait que certaines valeurs sont des substituts, et
qu'il doit SIGNALER une incohérence plutôt que la résoudre lui-même. Prix
assumé : la requête révèle à Anthropic qu'une couche existe. Elle ne révèle
aucune valeur, aucun substitut, aucune règle — seulement le fait.

Ce que l'annonce n'est PAS : un mécanisme de protection. Elle ne demande rien
au modèle, elle l'informe. La protection reste entièrement du côté du proxy —
c'est l'anti-patron §7 « anonymize en serveur MCP volontaire », et il ne faut
pas le réintroduire par la porte de derrière.

## Le canal de retour vers l'opérateur

Aucun canal hors bande n'existe : le proxy est transparent, il ne peut pas
interrompre une génération pour poser une question. Le canal, c'est la
CONVERSATION elle-même — le modèle s'adresse à l'opérateur, qui répond au tour
suivant. C'est déjà la boucle la plus naturelle, il suffit que le modèle sache
qu'elle lui est ouverte, et que l'opérateur ait de quoi y répondre :

    ./politique.sh arbitrer      révéler la valeur pour de bon
    (ou du texte libre)          expliquer comment faire sans elle

L'opérateur garde donc les deux issues, et c'est LUI qui tranche : révéler, ou
donner la stratégie. Le modèle propose, il ne décide pas.
"""
from __future__ import annotations

#: Réglages possibles de `ANONPROXY_ANNONCE`.
SILENCIEUX = "silencieux"
ANNONCE = "annonce"
MODES = (SILENCIEUX, ANNONCE)

#: Marqueur que le modèle est invité à employer. Il n'a aucune fonction
#: technique — rien ne le parse — mais il rend la demande repérable par
#: l'opérateur dans un flux de sortie long.
MARQUEUR = "[ANONYMISATION]"

TEXTE = f"""\
Certaines valeurs de cette conversation ont été remplacées par des substituts \
avant de t'être transmises : noms d'hôtes, adresses IP, dépôts, images, \
adresses e-mail, identifiants de service. Les substituts sont plausibles et \
cohérents entre eux — tu ne peux pas les distinguer de vraies valeurs, et tu \
n'as pas à essayer. L'opérateur, lui, voit les valeurs réelles : ta réponse \
lui parvient retraduite, donc cite les valeurs telles que tu les vois.

Cette substitution peut introduire des INCOHÉRENCES apparentes. Un exemple \
réel : un document déclare un sous-réseau, et les adresses des machines \
semblent ne pas lui appartenir. La contradiction vient de la substitution, \
pas des données.

Quand tu rencontres une incohérence de cette nature :

1. Ne la résous pas toi-même et n'invente aucune explication. Ne « corrige » \
   pas silencieusement ce qui te paraît être une faute de frappe.
2. Signale-la explicitement à l'opérateur, en commençant la ligne par \
   {MARQUEUR}, en décrivant ce que tu observes et pourquoi cela te bloque.
3. Propose les pistes que tu vois, en indiquant ce que chacune supposerait.
4. Puis attends sa réponse. Il peut soit révéler la valeur réelle, soit te \
   dire comment procéder sans elle — c'est lui qui décide, pas toi.

N'emploie ce marqueur que pour une incohérence liée à la substitution. Pour \
tout le reste, travaille normalement : la couche est transparente et n'a pas \
à être commentée."""


def bloc_systeme() -> dict:
    """Bloc `system` à ajouter au corps de la requête.

    Ajouté APRÈS la pseudonymisation : ce texte est le nôtre, il n'a rien à
    faire traverser au détecteur — qui y trouverait d'ailleurs des noms
    d'entités à substituer.

    Sans `cache_control` : le bloc est constant d'un tour à l'autre et se
    place APRÈS les points de césure posés par le client, donc le préfixe
    déjà mis en cache reste valide.
    """
    return {"type": "text", "text": TEXTE}


def injecter(corps: dict, mode: str) -> dict:
    """Ajoute l'annonce au corps si le mode le demande.

    Le corps est modifié EN PLACE puis rendu : c'est le corps sûr, déjà
    pseudonymisé, qui part à l'amont.
    """
    if mode != ANNONCE or not isinstance(corps, dict):
        return corps
    systeme = corps.get("system")
    if systeme is None:
        corps["system"] = [bloc_systeme()]
    elif isinstance(systeme, str):
        # La forme chaîne est la plus simple de l'API : on y concatène plutôt
        # que de la muer en liste, ce qui changerait la forme de la requête.
        corps["system"] = f"{systeme}\n\n{TEXTE}"
    elif isinstance(systeme, list):
        corps["system"] = [*systeme, bloc_systeme()]
    return corps
