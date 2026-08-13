"""Le PROJET est celui qu'on a lancé, pas le segment numéro deux.

Trouvé par ada en surveillant une session réelle : `/home/ada/lab/ai/anonproxy-demo`
sortait en `/home/<fictif>/<fictif>/ai/anonproxy-demo`. Le nom du DÉPÔT partait
donc en clair — et un dépôt porte très souvent le nom du client — pendant qu'un
répertoire d'organisation sans intérêt (`lab`) était masqué pour rien.

La règle supposait `/home/<utilisateur>/<projet>/…` et substituait les indices
1 et 2. C'est un pari sur la disposition des répertoires de l'opérateur, et il
échoue dès que le projet n'est pas directement sous le home.

Or le lanceur EXPORTE `ANONPROXY_PROJECT` : le chemin exact du projet est
connu, il n'y a rien à deviner. Deviner une position là où on dispose du fait
est la même erreur que déduire une position d'un nom de clé dans le walker.

Deux effets, dans les deux sens : le nom du dépôt cesse de fuir, et les
répertoires intermédiaires cessent d'être bruités.
"""
from __future__ import annotations

import pytest

from anonproxy.modes import (CHEMINS_COMPLET, CHEMINS_UTILISATEUR,
                             CHEMINS_UTILISATEUR_PROJET)
from anonproxy.policy import Policy
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "f6" * 32
PROJET = "/home/ada/lab/ai/anonproxy-demo"


@pytest.fixture
def moteur(tmp_path):
    def build(chemins=CHEMINS_UTILISATEUR_PROJET, projet=PROJET):
        politique = Policy(racine=tmp_path / f"pol-{chemins}-{projet}",
                           master_key=MASTER, scope_key="project:t")
        politique.definir_reglage("projet", "chemins", chemins)
        return SurrogateEngine(
            vault=Vault(tmp_path / f"{chemins}-{projet}.db",
                        master_key=MASTER),
            master_key=MASTER, scope_key="project:t", policy=politique,
            projet=projet)
    return build


def segments(chemin: str) -> list[str]:
    return [p for p in chemin.split("/") if p]


def test_le_nom_du_depot_ne_sort_pas_en_clair(moteur):
    rendu = moteur().substitute_value("FILE_PATH", f"{PROJET}/infra/inventaire.md")
    assert "anonproxy-demo" not in rendu, rendu
    assert "ada" not in segments(rendu), rendu


def test_un_chemin_COMPOSE_par_le_modele_se_restaure(moteur):
    """Le défaut qui a cassé une session réelle : `Read` a reçu un chemin
    FICTIF et a répondu « File does not exist », là où `cat` fonctionnait.

    Les segments étaient tirés du lexique DIRECTEMENT, sans passer par le
    coffre : seul le chemin ENTIER y était enregistré. Dès que le modèle
    compose un autre fichier du même dossier — le geste le plus ordinaire d'un
    agent — plus rien ne se restaure. Et rien ne le signale : un substitut
    jamais enregistré n'apparaît pas non plus dans `unresolved`, donc le
    compteur reste à zéro. C'est le critique du round 2, mot pour mot
    (`_fake_authority` appelait `_fake_host` hors du coffre), jamais corrigé
    pour les chemins.
    """
    m = moteur()
    lu = f"{PROJET}/infra/inventaire.md"
    faux = m.substitute_value("FILE_PATH", lu)
    vue = m.surrogates_view()

    compose = faux.replace("inventaire.md", "incident-4218.md")
    restaure = compose
    for f, reel in sorted(vue.items(), key=lambda kv: -len(kv[0])):
        restaure = restaure.replace(f, reel)
    assert restaure == f"{PROJET}/infra/incident-4218.md", restaure


def test_chaque_segment_substitue_est_au_coffre(moteur):
    """Le corollaire D6 : un substitut tiré hors du coffre reste LIBRE, donc
    une autre valeur réelle peut l'obtenir — et la restauration désignerait
    alors la mauvaise chose."""
    m = moteur()
    faux = m.substitute_value("FILE_PATH", f"{PROJET}/infra")
    vue = m.surrogates_view()
    inconnus = [s for s in faux.split("/")
                if s and s not in ("home", "lab", "ai", "infra")
                and s not in vue]
    assert not inconnus, f"segments hors coffre : {inconnus}"


def test_un_meme_token_garde_une_seule_identite(moteur):
    """Le modèle voyait `ada` sous deux noms selon qu'il le lisait comme une
    PERSONNE ou comme un segment de chemin — la classe critique du round 2
    (« un hôte vu comme HOSTNAME/FQDN/CERT_CN recevait jusqu'à 4 identités »),
    jamais fermée pour les chemins. Passer les segments par le COFFRE la ferme
    par construction : c'est la clé canonique qui décide, pas le type du span."""
    m = moteur()
    par_segment = m.substitute_value("PATH_SEGMENT", "ada")
    assert m.substitute_value("PERSON", "ada") == par_segment
    assert par_segment in m.substitute_value("FILE_PATH", "/home/ada/x").split("/")


@pytest.mark.parametrize("chemin", [
    "/home/./ada/lab/ai/anonproxy-demo/infra",
    "/home/../ada/lab/ai/anonproxy-demo/infra",
    "/./home/ada/lab/ai/anonproxy-demo/infra",
    "/home/ada/../ada/lab/ai/anonproxy-demo/infra",
])
def test_un_segment_point_ne_decale_pas_la_regle(moteur, chemin):
    """DEUX défauts qui se composaient, et le résultat était le pire possible.

    `.` et `..` sont des segments comme les autres pour `split`, donc un `.`
    à l'indice 1 décalait l'utilisateur à l'indice 2 — une position CONSERVÉE.
    Et comme un `.` n'a aucun caractère alphanumérique, il se substitue à
    lui-même : le chemin reconstruit devenait IDENTIQUE à l'original, les 64
    tentatives tombaient toutes en identité, et la garde qui rend une valeur
    « sans rien à cacher » rendait le chemin ENTIER — utilisateur et nom de
    dépôt compris, sans une seule entrée de coffre pour le signaler.

    Un chemin absolu qui porte `.` ou `..` est ANORMAL : c'est exactement le
    moment de fermer, pas d'appliquer une règle de position."""
    rendu = moteur().substitute_value("FILE_PATH", chemin)
    assert rendu != chemin, rendu
    assert "ada" not in segments(rendu), rendu
    assert "anonproxy-demo" not in segments(rendu), rendu


def test_les_repertoires_intermediaires_restent(moteur):
    """`lab` et `ai` n'identifient personne : les masquer coûte de la lisibilité
    au modèle sans rien protéger."""
    rendu = segments(moteur().substitute_value("FILE_PATH", f"{PROJET}/infra"))
    assert rendu[0] == "home" and rendu[2] == "lab" and rendu[3] == "ai"


def test_le_chemin_relatif_dans_le_projet_reste_lisible(moteur):
    """Ce que le modèle doit pouvoir citer pour travailler."""
    rendu = moteur().substitute_value("FILE_PATH", f"{PROJET}/infra/inventaire.md")
    assert rendu.endswith("/infra/inventaire.md"), rendu


def test_sans_le_projet_seul_l_utilisateur_sort(moteur):
    """Réglage `utilisateur` : le dépôt reste, c'est le choix de l'opérateur."""
    rendu = moteur(chemins=CHEMINS_UTILISATEUR).substitute_value(
        "FILE_PATH", f"{PROJET}/infra")
    assert rendu.endswith("/lab/ai/anonproxy-demo/infra"), rendu
    assert "ada" not in segments(rendu)


def test_complet_masque_tout(moteur):
    rendu = moteur(chemins=CHEMINS_COMPLET).substitute_value("FILE_PATH", PROJET)
    assert "anonproxy-demo" not in rendu and "lab" not in segments(rendu)


def test_un_chemin_hors_projet_garde_sa_structure(moteur):
    """Hors du projet, il n'y a plus de nom de dépôt à reconnaître : seul
    l'utilisateur sort."""
    rendu = moteur().substitute_value("FILE_PATH", "/home/ada/autre/chose.txt")
    assert rendu.endswith("/autre/chose.txt") and "ada" not in segments(rendu)


def test_projet_inconnu_garde_le_pari_positionnel(moteur):
    """Sans `ANONPROXY_PROJECT`, on ne sait pas où est le dépôt — et ne rien
    masquer le laisserait sortir en clair dans la disposition la plus courante,
    `/home/<utilisateur>/<projet>`. Le pari de position RESTE donc en repli :
    masquer un répertoire de trop est visible et réparable, laisser sortir un
    nom de dépôt ne l'est pas."""
    rendu = segments(moteur(projet=None).substitute_value(
        "FILE_PATH", "/home/ada/acme-nda/notes.md"))
    assert "ada" not in rendu and "acme-nda" not in rendu
    assert rendu[-1] == "notes.md"
