"""Lexiques de substitution — vocabulaire neutre et plausible (D1).

Aucun mot n'est un marqueur : pas de « pseudo- », pas de « fake », pas de
« .invalid ». Les substituts doivent être indiscernables de vraies valeurs,
sinon le modèle « répare » l'anomalie en inventant des entités.

Le lexique d'identités est **volontairement unique et neutre** : on ne
préserve ni l'origine ni le genre d'un nom (plan §5, tâche 2). Rien de
légitime n'en dépend.
"""
from __future__ import annotations

# Mots de service / composants — domaine métier générique, crédible en infra.
SERVICE_WORDS: tuple[str, ...] = (
    "billing", "invoice", "roster", "gateway", "registry", "planner", "vault",
    "cluster", "runner", "broker", "session", "policy", "digest", "harbor",
    "beacon", "atlas", "quarry", "lantern", "meadow", "compass", "anchor",
    "canyon", "delta", "ember", "fjord", "glacier", "harbour", "island",
    "juniper", "kestrel", "lagoon", "mesa", "nimbus", "onyx", "prairie",
    "quartz", "ridge", "summit", "tundra", "umber", "valley", "willow",
    "xenon", "yarrow", "zephyr", "alcove", "bramble", "cedar", "dune",
    "estuary", "fern", "gorge", "heather", "inlet", "jetty", "knoll",
    "larch", "moss", "nettle", "orchard", "pebble", "reef", "sedge",
    "thicket", "upland", "vale", "wharf", "yew", "arbor", "basin", "creek",
)

# Étiquettes d'organisation / d'équipe — utilisées pour les zones DNS et orgs.
ORG_WORDS: tuple[str, ...] = (
    "northwind", "contoso", "fabrikam", "wingtip", "litware", "adventure",
    "proseware", "tailspin", "woodgrove", "lucerne", "trey", "alpine",
    "coho", "fourth", "graphic", "humongous", "lamna", "margie", "nod",
    "olympic", "parnell", "relecloud", "southridge", "tasman", "vanarsdel",
    "wide", "blue", "consolidated", "fineart", "school", "city", "first",
)

# Identités humaines — lexique unique, neutre, sans marqueur d'origine.
IDENTITY_WORDS: tuple[str, ...] = (
    "avery", "bailey", "casey", "darcy", "ellis", "finley", "gray", "harper",
    "indigo", "jules", "kai", "lane", "morgan", "noel", "oakley", "paris",
    "quinn", "reese", "sage", "tatum", "vale", "wren", "yale", "zion",
    "arden", "blake", "cameron", "devon", "emery", "frankie", "george",
    "hayden", "isley", "jamie", "kendall", "logan", "marlow", "nico",
    "ollie", "peyton", "riley", "shea", "teagan", "urban", "vesper",
    "winter", "york", "ziggy", "ashton", "briar", "corey", "dallas",
)

# Suffixes de comptes de service (préserve « service » vs « humain »).
SERVICE_ACCOUNT_WORDS: tuple[str, ...] = (
    "agent", "bot", "daemon", "job", "runner", "sync", "worker", "collector",
    "exporter", "operator", "scheduler", "reconciler", "publisher", "indexer",
)

# TLD/suffixes plausibles pour les domaines externes fictifs.
EXTERNAL_TLDS: tuple[str, ...] = ("com", "net", "io", "org", "co", "dev")

# Registres publics plausibles pour les images de conteneurs privées.
REGISTRY_WORDS: tuple[str, ...] = ("registry", "harbor", "images", "artifacts", "docker")


def pick(words: tuple[str, ...], index: int) -> str:
    return words[index % len(words)]
