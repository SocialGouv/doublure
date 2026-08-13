"""La politique de confidentialité : fermée par défaut, ouverte par l'opérateur.

Ce qui est vérifié ici tient en une phrase : **rien ne sort sans une décision
explicite**, et la seule décision qui fasse sortir quelque chose ne peut être
prise ni par défaut, ni par accident, ni sur un secret.
"""
from __future__ import annotations

import json
import time

import pytest

from anonproxy.policy import Decision, PolitiqueInvalide, Policy
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "c3" * 32
SCOPE = "project:essai"

HOTE = "db-master-01-prod.acmecorp.internal"


def make_policy(tmp_path, session=None):
    return Policy(racine=tmp_path / "policy", master_key=MASTER,
                  scope_key=SCOPE, session=session)


def make_engine(tmp_path, politique, nom="v"):
    return SurrogateEngine(
        vault=Vault(tmp_path / f"{nom}.db", master_key=MASTER),
        master_key=MASTER, scope_key=SCOPE, policy=politique)


# --------------------------------------------------------------------------- #
# Le défaut
# --------------------------------------------------------------------------- #
def test_sans_regle_tout_est_anonymise(tmp_path):
    politique = make_policy(tmp_path)
    decision, source = politique.decide("HOSTNAME", "infra", HOTE)
    assert decision is Decision.ANONYMISER
    assert source is None, "aucune règle ne doit prétendre avoir décidé"


def test_le_defaut_substitue_vraiment(tmp_path):
    moteur = make_engine(tmp_path, make_policy(tmp_path))
    assert moteur.substitute_value("HOSTNAME", HOTE) != HOTE


# --------------------------------------------------------------------------- #
# Les trois granularités
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("granularite,cle", [
    ("classe", "infra"),
    ("type", "HOSTNAME"),
])
def test_reveler_par_classe_ou_par_type(tmp_path, granularite, cle):
    politique = make_policy(tmp_path)
    politique.definir("projet", granularite, cle, Decision.REVELER)
    moteur = make_engine(tmp_path, politique)
    assert moteur.substitute_value("HOSTNAME", HOTE) == HOTE


def test_reveler_une_seule_valeur(tmp_path):
    politique = make_policy(tmp_path)
    politique.definir("projet", "valeur",
                      politique.empreinte("HOSTNAME", HOTE.lower()),
                      Decision.REVELER)
    moteur = make_engine(tmp_path, politique)
    assert moteur.substitute_value("HOSTNAME", HOTE) == HOTE
    # …et elle SEULE : la machine voisine reste anonymisée.
    voisin = "db-replica-02-prod.acmecorp.internal"
    assert moteur.substitute_value("HOSTNAME", voisin) != voisin


def test_une_decision_de_valeur_vaut_pour_les_variantes_de_casse(tmp_path):
    """Le DNS est insensible à la casse : deux écritures, une seule décision."""
    politique = make_policy(tmp_path)
    politique.definir("projet", "valeur",
                      politique.empreinte("HOSTNAME", HOTE.lower()),
                      Decision.REVELER)
    moteur = make_engine(tmp_path, politique)
    majuscules = HOTE.upper()
    assert moteur.substitute_value("HOSTNAME", majuscules) == majuscules


# --------------------------------------------------------------------------- #
# Les résolutions — c'est là que se cachent les surprises
# --------------------------------------------------------------------------- #
def test_la_granularite_la_plus_precise_l_emporte(tmp_path):
    """« les hôtes en général : révéler, mais CELUI-CI : anonymiser »."""
    politique = make_policy(tmp_path)
    politique.definir("projet", "type", "HOSTNAME", Decision.REVELER)
    politique.definir("projet", "valeur",
                      politique.empreinte("HOSTNAME", HOTE.lower()),
                      Decision.ANONYMISER)
    moteur = make_engine(tmp_path, politique)
    assert moteur.substitute_value("HOSTNAME", HOTE) != HOTE
    autre = "web-01-prod.acmecorp.internal"
    assert moteur.substitute_value("HOSTNAME", autre) == autre


def test_la_portee_la_plus_proche_l_emporte(tmp_path):
    """La session prime sur le projet, qui prime sur le global."""
    politique = make_policy(tmp_path, session="s1")
    politique.definir("global", "type", "HOSTNAME", Decision.REVELER)
    politique.definir("projet", "type", "HOSTNAME", Decision.ANONYMISER)
    assert politique.decide("HOSTNAME", "infra", HOTE)[1] == "projet:type"
    politique.definir("session", "type", "HOSTNAME", Decision.REVELER)
    assert politique.decide("HOSTNAME", "infra", HOTE)[1] == "session:type"


def test_le_global_sert_de_defaut_au_projet(tmp_path):
    politique = make_policy(tmp_path)
    politique.definir("global", "classe", "infra", Decision.REVELER)
    moteur = make_engine(tmp_path, politique)
    assert moteur.substitute_value("HOSTNAME", HOTE) == HOTE


# --------------------------------------------------------------------------- #
# D4 — un secret ne se révèle jamais, et le refus est à l'ÉCRITURE
# --------------------------------------------------------------------------- #
def test_la_classe_secret_ne_peut_pas_etre_revelee(tmp_path):
    politique = make_policy(tmp_path)
    with pytest.raises(PolitiqueInvalide, match="jamais révélable"):
        politique.definir("global", "classe", "secret", Decision.REVELER)


def test_meme_une_regle_de_type_ne_revele_pas_un_secret(tmp_path):
    """Écrire la règle est possible ; elle reste sans effet — D4 prime.

    Le refus à l'écriture ne couvre que la classe : rien n'empêche d'écrire
    `type:AUTH_TOKEN = reveler`. C'est l'invariant, pas la validation, qui
    doit tenir.
    """
    politique = make_policy(tmp_path)
    politique.definir("projet", "type", "AUTH_TOKEN", Decision.REVELER)
    decision, source = politique.decide("AUTH_TOKEN", "secret", "ghp_" + "a" * 36)
    assert decision is Decision.ANONYMISER
    assert source == "invariant:D4"
    moteur = make_engine(tmp_path, politique)
    jeton = "ghp_" + "b" * 36
    assert moteur.substitute_value("AUTH_TOKEN", jeton) != jeton


# --------------------------------------------------------------------------- #
# Le fichier de politique ne contient AUCUNE valeur réelle
# --------------------------------------------------------------------------- #
def test_le_fichier_ne_contient_pas_la_valeur(tmp_path):
    politique = make_policy(tmp_path)
    politique.definir("projet", "valeur",
                      politique.empreinte("HOSTNAME", HOTE), Decision.REVELER)
    brut = (tmp_path / "policy").glob("*.json")
    contenu = "\n".join(p.read_text(encoding="utf-8") for p in brut)
    assert HOTE not in contenu
    assert "acmecorp" not in contenu
    assert "db-master" not in contenu


def test_l_empreinte_depend_du_type(tmp_path):
    """La même chaîne vue comme hôte ou comme chemin n'est pas la même décision."""
    politique = make_policy(tmp_path)
    assert politique.empreinte("HOSTNAME", HOTE) != politique.empreinte("FILE_PATH", HOTE)


# --------------------------------------------------------------------------- #
# La file d'arbitrage
# --------------------------------------------------------------------------- #
def test_une_valeur_sans_regle_pose_une_question(tmp_path):
    politique = make_policy(tmp_path)
    moteur = make_engine(tmp_path, politique)
    substitut = moteur.substitute_value("HOSTNAME", HOTE)
    questions = politique.questions()
    assert len(questions) == 1
    q = questions[0]
    assert q["type"] == "HOSTNAME" and q["classe"] == "infra"
    assert q["substitut"] == substitut


def test_la_question_ne_contient_pas_la_valeur_reelle(tmp_path):
    politique = make_policy(tmp_path)
    make_engine(tmp_path, politique).substitute_value("HOSTNAME", HOTE)
    brut = (tmp_path / "policy" / "en-attente.jsonl").read_text(encoding="utf-8")
    assert HOTE not in brut and "acmecorp" not in brut
    # …mais elle porte de quoi retrouver la valeur pour l'opérateur.
    assert json.loads(brut.splitlines()[0])["substitut"]


def test_une_valeur_deja_reglee_ne_pose_pas_de_question(tmp_path):
    politique = make_policy(tmp_path)
    politique.definir("projet", "type", "HOSTNAME", Decision.ANONYMISER)
    make_engine(tmp_path, politique).substitute_value("HOSTNAME", HOTE)
    assert politique.questions() == []


def test_repondre_fait_disparaitre_la_question(tmp_path):
    politique = make_policy(tmp_path)
    make_engine(tmp_path, politique).substitute_value("HOSTNAME", HOTE)
    assert len(politique.questions()) == 1
    politique.definir("projet", "type", "HOSTNAME", Decision.REVELER)
    assert politique.questions() == []


def test_l_operateur_peut_retrouver_la_valeur_via_le_coffre(tmp_path):
    """La file ne révèle rien, mais l'arbitrage doit rester possible."""
    politique = make_policy(tmp_path)
    moteur = make_engine(tmp_path, politique)
    moteur.substitute_value("HOSTNAME", HOTE)
    question = politique.questions()[0]
    assert moteur.vault.view(SCOPE)[question["substitut"]] == HOTE.lower()


# --------------------------------------------------------------------------- #
# Fail-closed
# --------------------------------------------------------------------------- #
def test_une_politique_illisible_anonymise(tmp_path):
    """Un fichier corrompu ne doit rien OUVRIR — il n'ouvrait rien avant."""
    politique = make_policy(tmp_path)
    politique.definir("projet", "type", "HOSTNAME", Decision.REVELER)
    politique._fichiers["projet"].write_text("{ ceci n'est pas du JSON",
                                             encoding="utf-8")
    assert politique.decide("HOSTNAME", "infra", HOTE)[0] is Decision.ANONYMISER
    moteur = make_engine(tmp_path, politique)
    assert moteur.substitute_value("HOSTNAME", HOTE) != HOTE


def test_une_decision_inconnue_est_ignoree(tmp_path):
    politique = make_policy(tmp_path)
    politique._fichiers["projet"].parent.mkdir(parents=True, exist_ok=True)
    politique._fichiers["projet"].write_text(
        json.dumps({"type": {"HOSTNAME": "peut-etre"}}), encoding="utf-8")
    assert politique.decide("HOSTNAME", "infra", HOTE)[0] is Decision.ANONYMISER


def test_une_portee_ou_une_granularite_inconnue_est_refusee(tmp_path):
    politique = make_policy(tmp_path)
    with pytest.raises(PolitiqueInvalide):
        politique.definir("tenant", "type", "HOSTNAME", Decision.REVELER)
    with pytest.raises(PolitiqueInvalide):
        politique.definir("projet", "sous-type", "HOSTNAME", Decision.REVELER)


def test_sans_politique_le_moteur_anonymise_comme_avant(tmp_path):
    """La couche ne peut qu'ouvrir : absente, le comportement est inchangé."""
    moteur = SurrogateEngine(vault=Vault(tmp_path / "n.db", master_key=MASTER),
                             master_key=MASTER, scope_key=SCOPE)
    assert moteur.substitute_value("HOSTNAME", HOTE) != HOTE


# --------------------------------------------------------------------------- #
# Annoncer, ou non, la couche au modèle
# --------------------------------------------------------------------------- #
from anonproxy.annonce import ANNONCE, MARQUEUR, SILENCIEUX, TEXTE, injecter  # noqa: E402


def test_silencieux_ne_touche_a_rien():
    corps = {"system": "tu es utile", "messages": []}
    assert injecter(dict(corps), SILENCIEUX) == corps


@pytest.mark.parametrize("systeme,verifie", [
    (None, lambda c: c["system"][-1]["text"] == TEXTE),
    ("consigne", lambda c: c["system"].startswith("consigne") and TEXTE in c["system"]),
    ([{"type": "text", "text": "consigne"}],
     lambda c: len(c["system"]) == 2 and c["system"][0]["text"] == "consigne"),
])
def test_l_annonce_s_ajoute_sans_ecraser(systeme, verifie):
    """Le `system` du client a trois formes possibles : aucune ne se perd."""
    corps = {"messages": []}
    if systeme is not None:
        corps["system"] = systeme
    assert verifie(injecter(corps, ANNONCE))


def test_l_annonce_ne_pose_pas_de_point_de_cache():
    """Le bloc ajouté ne doit pas déplacer les césures posées par le client."""
    corps = injecter({"system": [{"type": "text", "text": "x",
                                  "cache_control": {"type": "ephemeral"}}]},
                     ANNONCE)
    assert corps["system"][0].get("cache_control")
    assert "cache_control" not in corps["system"][1]


def test_l_annonce_dit_au_modele_de_ne_pas_deviner():
    """Le contenu est la fonctionnalité : ces trois consignes sont le contrat."""
    assert MARQUEUR in TEXTE
    assert "n'invente" in TEXTE and "Ne la résous pas toi-même" in TEXTE
    assert "c'est lui qui décide" in TEXTE


def test_un_reglage_d_environnement_inconnu_est_refuse(tmp_path, monkeypatch):
    """Une faute de frappe retomberait en silence sur le défaut : refus.

    La validation vit à UN seul endroit (`modes.valide`) : en avoir une
    seconde dans `Settings` les aurait fait diverger.
    """
    monkeypatch.setenv("ANONPROXY_ANNONCE", "anonce")
    with pytest.raises(ReglageInvalide, match="annonce"):
        make_policy(tmp_path).reglage("annonce")


def test_un_mode_d_environnement_inconnu_est_refuse(tmp_path, monkeypatch):
    monkeypatch.setenv("ANONPROXY_MODE", "rapide")
    with pytest.raises(ReglageInvalide, match="ANONPROXY_MODE"):
        make_policy(tmp_path).mode()


# --------------------------------------------------------------------------- #
# Modes — des JEUX de réglages, résolus par la MÊME hiérarchie que les règles
# --------------------------------------------------------------------------- #
from anonproxy.modes import (  # noqa: E402
    ARBITRAGE_BLOQUANT, ARBITRAGE_DIFFERE, DELAI_ARBITRAGE, DOMAINES_RESERVES,
    MODE_DEFAUT, ReglageInvalide,
)


def test_le_mode_par_defaut_est_auto(tmp_path):
    assert make_policy(tmp_path).mode() == MODE_DEFAUT == "auto"


def test_un_mode_pose_plusieurs_reglages_d_un_coup(tmp_path):
    politique = make_policy(tmp_path)
    politique.definir_reglage("projet", "mode", "consciencieux")
    assert politique.reglage("arbitrage") == ARBITRAGE_BLOQUANT
    assert politique.reglage("domaines_fictifs") == DOMAINES_RESERVES
    assert politique.reglage(DELAI_ARBITRAGE) == 120


def test_un_reglage_se_surcharge_individuellement(tmp_path):
    """C'est ce qui distingue un mode d'un comportement opaque."""
    politique = make_policy(tmp_path)
    politique.definir_reglage("projet", "mode", "consciencieux")
    politique.definir_reglage("projet", "arbitrage", ARBITRAGE_DIFFERE)
    assert politique.reglage("arbitrage") == ARBITRAGE_DIFFERE
    assert politique.reglage("domaines_fictifs") == DOMAINES_RESERVES  # inchangé


def test_la_portee_la_plus_proche_l_emporte_aussi_pour_les_reglages(tmp_path):
    politique = make_policy(tmp_path, session="s1")
    politique.definir_reglage("global", "annonce", "annonce")
    politique.definir_reglage("projet", "annonce", "silencieux")
    assert politique.reglage("annonce") == "silencieux"
    politique.definir_reglage("session", "annonce", "annonce")
    assert politique.reglage("annonce") == "annonce"


def test_l_environnement_prime_sur_les_fichiers(tmp_path, monkeypatch):
    """Levier de dépannage : il doit gagner sur un fichier qu'on ne relit pas."""
    politique = make_policy(tmp_path)
    politique.definir_reglage("session", "annonce", "silencieux")
    monkeypatch.setenv("ANONPROXY_ANNONCE", "annonce")
    assert politique.reglage("annonce") == "annonce"


@pytest.mark.parametrize("nom,valeur", [
    ("mode", "rapide"), ("arbitrage", "peut-etre"),
    ("annonce", "anonce"), ("domaines_fictifs", "n_importe"),
    (DELAI_ARBITRAGE, "-5"), (DELAI_ARBITRAGE, "beaucoup"),
])
def test_une_valeur_de_reglage_inconnue_est_refusee(tmp_path, nom, valeur):
    with pytest.raises(ReglageInvalide):
        make_policy(tmp_path).definir_reglage("projet", nom, valeur)


def test_aucun_mode_ne_s_ecarte_d_un_reglage_de_protection():
    """L'invariant que le test suivant PORTAIT dans son nom sans le vérifier.

    Il montrait qu'un hôte est bien substitué sous chaque mode — vrai, mais
    beaucoup plus étroit que « aucun mode n'ouvre ». `auto`, le mode par
    DÉFAUT, tirait ses domaines fictifs de TLD réels quand les deux autres
    restaient dans l'espace réservé : choisir un mode revenait donc à ouvrir,
    et rien ne le voyait. Un réglage de protection doit être identique partout ;
    seuls ceux qui décident de l'INTERACTION peuvent varier.
    """
    from anonproxy.modes import MODES, REGLAGES_DE_PROTECTION

    for reglage in REGLAGES_DE_PROTECTION:
        valeurs = {nom: mode[reglage] for nom, mode in MODES.items()}
        assert len(set(valeurs.values())) == 1, (
            f"le réglage de protection {reglage!r} varie selon le mode : "
            f"{valeurs} — un mode ne choisit pas SI on protège")


def test_aucun_mode_n_ouvre_quoi_que_ce_soit(tmp_path):
    """Un mode choisit QUAND l'opérateur est sollicité, jamais SI on protège."""
    from anonproxy.modes import MODES

    for nom in MODES:
        politique = make_policy(tmp_path / nom)
        politique.definir_reglage("projet", "mode", nom)
        assert politique.decide("HOSTNAME", "infra", HOTE)[0] is Decision.ANONYMISER
        moteur = make_engine(tmp_path / nom, politique, nom="m")
        assert moteur.substitute_value("HOSTNAME", HOTE) != HOTE


def test_le_mode_bloquant_anonymise_a_l_echeance(tmp_path):
    """Un délai dépassé ne vaut JAMAIS un consentement."""
    politique = make_policy(tmp_path)
    politique.definir_reglage("projet", "arbitrage", ARBITRAGE_BLOQUANT)
    politique.definir_reglage("projet", DELAI_ARBITRAGE, 1)
    moteur = make_engine(tmp_path, politique)
    assert moteur.substitute_value("HOSTNAME", HOTE) != HOTE


def test_le_mode_bloquant_prend_la_decision_rendue(tmp_path):
    """L'opérateur répond depuis un AUTRE processus : on relit le fichier."""
    import threading

    politique = make_policy(tmp_path)
    politique.definir_reglage("projet", "arbitrage", ARBITRAGE_BLOQUANT)
    politique.definir_reglage("projet", DELAI_ARBITRAGE, 10)
    moteur = make_engine(tmp_path, politique)

    def repond():
        autre = make_policy(tmp_path)          # instance distincte, comme la CLI
        for _ in range(100):
            if autre.questions():
                autre.definir("projet", "type", "HOSTNAME", Decision.REVELER)
                return
            time.sleep(0.05)

    fil = threading.Thread(target=repond)
    fil.start()
    resultat = moteur.substitute_value("HOSTNAME", HOTE)
    fil.join()
    assert resultat == HOTE, "la décision rendue pendant l'attente doit s'appliquer"


def test_les_domaines_reserves_ne_sont_a_personne(tmp_path):
    """Les deux réglages marchent — mais le DÉFAUT ferme, et il a changé.

    Ce test épinglait l'inverse : sans réglage explicite, un hôte externe
    recevait un TLD réel. C'était l'ouverture par défaut, et elle tenait à ce
    que la condition du moteur teste `reserves` — donc à ce que tout ce qui
    n'était pas explicitement FERMÉ soit ouvert. Le mode `auto`, mode par
    DÉFAUT, portait la valeur permissive quand les deux autres portaient
    l'autre : choisir un mode revenait à ouvrir.

    `tld_reels` reste atteignable ; il faut le DÉCLARER."""
    from anonproxy.modes import DOMAINES_TLD_REELS
    from anonproxy.surrogates.lexicon import EXTERNAL_TLDS, RESERVED_TLDS

    externe = "www-01.acmecorp-externe.fr"
    politique = make_policy(tmp_path)
    politique.definir_reglage("projet", "domaines_fictifs", DOMAINES_RESERVES)
    faux = make_engine(tmp_path, politique).substitute_value("HOSTNAME", externe)
    assert faux.rsplit(".", 1)[-1] in RESERVED_TLDS, faux

    ouverte = make_policy(tmp_path / "b")
    ouverte.definir_reglage("projet", "domaines_fictifs", DOMAINES_TLD_REELS)
    faux2 = make_engine(tmp_path / "b", ouverte, nom="c").substitute_value(
        "HOSTNAME", externe)
    assert faux2.rsplit(".", 1)[-1] in EXTERNAL_TLDS, faux2

    muette = make_policy(tmp_path / "c")
    faux3 = make_engine(tmp_path / "c", muette, nom="d").substitute_value(
        "HOSTNAME", externe)
    assert faux3.rsplit(".", 1)[-1] in RESERVED_TLDS, faux3


def test_une_revelation_de_portee_session_ne_traverse_pas_les_portees(tmp_path):
    """HAUT. La portée la plus ÉTROITE débordait plus large que la portée
    projet, qui, elle, était bien séparée.

    `session-<id>.json` ne portait pas le scope_key : deux portées partageant
    une racine de politique lisaient le MÊME fichier, et une décision
    « révéler » y traversait. Le nom de session par défaut étant `sans-id`, la
    collision était le cas ORDINAIRE dès que la racine est partagée.

    « Révéler ne s'hérite jamais d'un défaut » — et traverser une portée est
    une forme d'héritage."""
    racine = tmp_path / "policy"
    alpha = Policy(racine=racine, master_key=MASTER, scope_key="project:alpha",
                   session="s-42")
    beta = Policy(racine=racine, master_key=MASTER, scope_key="project:beta",
                  session="s-42")

    alpha.definir("session", "valeur", alpha.empreinte("HOSTNAME", HOTE),
                  Decision.REVELER)
    assert alpha.decide("HOSTNAME", "infra", HOTE)[0] is Decision.REVELER
    assert beta.decide("HOSTNAME", "infra", HOTE)[0] is Decision.ANONYMISER, \
        "la révélation d'une portée a traversé vers une autre"


def test_deux_portees_sans_identifiant_de_session_ne_se_melangent_pas(tmp_path):
    """Le cas ORDINAIRE : sans `ANONPROXY_SESSION`, les deux retombaient sur
    `session-sans-id.json`, donc sur le même fichier."""
    racine = tmp_path / "policy"
    alpha = Policy(racine=racine, master_key=MASTER, scope_key="project:alpha")
    beta = Policy(racine=racine, master_key=MASTER, scope_key="project:beta")
    assert alpha._fichiers["session"] != beta._fichiers["session"]

    alpha.definir("session", "type", "HOSTNAME", Decision.REVELER)
    assert beta.decide("HOSTNAME", "infra", HOTE)[0] is Decision.ANONYMISER


def test_la_meme_portee_se_retrouve_bien(tmp_path):
    """L'AUTRE MOITIÉ : séparer ne doit pas empêcher une portée de relire ce
    qu'elle a elle-même écrit, dans un autre processus."""
    racine = tmp_path / "policy"
    ecrit = Policy(racine=racine, master_key=MASTER, scope_key="project:alpha",
                   session="s-42")
    ecrit.definir("session", "valeur", ecrit.empreinte("HOSTNAME", HOTE),
                  Decision.REVELER)
    relu = Policy(racine=racine, master_key=MASTER, scope_key="project:alpha",
                  session="s-42")
    assert relu.decide("HOSTNAME", "infra", HOTE)[0] is Decision.REVELER


@pytest.mark.parametrize("a,b", [
    # `:` → `-` : deux notations d'une même intention, ordinaires en pratique.
    (("proj:client", None), ("proj-client", None)),
    # `/` → `_`
    (("team/prod", None), ("team_prod", None)),
    # le pire : un PROJET nommé comme l'infixe de session d'un autre
    (("acme-session-prod", None), ("acme", "prod")),
])
def test_deux_projets_distincts_n_ecrivent_jamais_le_meme_fichier(tmp_path, a, b):
    """CRITIQUE. **Substituer des caractères ne peut pas être injectif** : des
    portées distinctes tombaient sur le même fichier, donc une décision
    « révéler » de l'une s'appliquait à l'autre.

    Le dernier cas est celui que MON correctif précédent a créé : l'infixe
    `-session-` posé pour séparer les sessions faisait collisionner le projet
    `acme-session-prod` avec la session `prod` du projet `acme` — à travers la
    portée ET le scope_key. Corriger un schéma d'échappement par un autre
    schéma d'échappement reproduit la classe ; ce qui décide est désormais
    l'empreinte du tuple exact.

    Deux SESSIONS d'un même projet ne sont PAS traitées ici : elles partagent
    délibérément leur fichier de portée projet, sinon une règle de projet ne
    vaudrait que pour la session qui l'a posée. C'est
    `test_une_regle_de_projet_vaut_dans_une_autre_session` qui tient ce
    bout-là."""
    (scope_a, sess_a), (scope_b, sess_b) = a, b
    racine = tmp_path / "policy"
    pa = Policy(racine=racine, master_key=MASTER, scope_key=scope_a, session=sess_a)
    pb = Policy(racine=racine, master_key=MASTER, scope_key=scope_b, session=sess_b)

    fichiers_a = {p: f for p, f in pa._fichiers.items() if p != "global"}
    fichiers_b = {p: f for p, f in pb._fichiers.items() if p != "global"}
    communs = set(fichiers_a.values()) & set(fichiers_b.values())
    assert not communs, f"deux portées écrivent {communs}"

    # Et la conséquence, mesurée : une révélation ne traverse pas.
    for portee in ("projet", "session"):
        pa.definir(portee, "type", "HOSTNAME", Decision.REVELER)
    assert pb.decide("HOSTNAME", "infra", HOTE)[0] is Decision.ANONYMISER


def test_un_scope_key_exotique_reste_lisible_et_relisible(tmp_path):
    """L'AUTRE MOITIÉ : rendre le nom injectif ne doit ni casser la relecture,
    ni rendre le répertoire illisible pour l'opérateur qui l'inspecte."""
    racine = tmp_path / "policy"
    for scope in ("tenant:acme/prod", "projet-accentué-éàü", "a" * 200, "::://"):
        ecrit = Policy(racine=racine, master_key=MASTER, scope_key=scope)
        ecrit.definir("projet", "type", "HOSTNAME", Decision.REVELER)
        relu = Policy(racine=racine, master_key=MASTER, scope_key=scope)
        assert relu.decide("HOSTNAME", "infra", HOTE)[0] is Decision.REVELER, scope
        nom = relu._fichiers["projet"].name
        assert nom.endswith(".json") and "/" not in nom and len(nom) < 80, nom


def test_un_reglage_d_environnement_invalide_refuse_le_demarrage(tmp_path, monkeypatch):
    """HAUT. Un réglage invalide dans l'environnement levait — mais à CHAQUE
    requête, au fond du pipeline. Une faute de frappe se lisait donc comme une
    panne du canal : socket coupée, message noyé dans une erreur d'échange.

    Le refus est le bon comportement (jamais de repli silencieux) ; c'est son
    MOMENT qui était faux. Il appartient au démarrage, comme pour le binaire de
    contrôle qui refuse de démarrer sans ses chemins d'état."""
    politique = make_policy(tmp_path)
    monkeypatch.setenv("ANONPROXY_MODE", "n_importe_quoi")
    with pytest.raises(ReglageInvalide, match="ANONPROXY_MODE"):
        politique.reglages_resolus()
    monkeypatch.delenv("ANONPROXY_MODE")
    monkeypatch.setenv("ANONPROXY_DOMAINES_FICTIFS", "n_importe")
    with pytest.raises(ReglageInvalide):
        politique.reglages_resolus()


def test_le_separateur_de_l_empreinte_ne_peut_pas_etre_injecte(tmp_path):
    """CRITIQUE. Le nommage par empreinte joignait les champs par `\\x1f` —
    donc dépendait, implicitement, de ce que ce caractère n'apparaisse jamais
    dans les données. Or `scope_key` et `session` viennent de variables
    d'environnement, sans filtre : `scope_key="\\x1f"` et `session="\\x1f"`
    produisaient la MÊME chaîne, donc le même fichier, donc une révélation qui
    traverse.

    C'est la classe de la veille, une couche plus bas : **un séparateur seul
    n'est pas plus injectif qu'une substitution de caractères** tant qu'il peut
    apparaître dans ce qu'il sépare. Chaque champ est maintenant préfixé par sa
    longueur."""
    racine = tmp_path / "policy"
    a = Policy(racine=racine, master_key=MASTER, scope_key="\x1f", session=None)
    b = Policy(racine=racine, master_key=MASTER, scope_key="", session="\x1f")
    for portee in ("projet", "session"):
        a.definir(portee, "type", "HOSTNAME", Decision.REVELER)
    assert b.decide("HOSTNAME", "infra", HOTE)[0] is Decision.ANONYMISER


def test_une_regle_de_projet_vaut_dans_une_autre_session(tmp_path):
    """HAUT, FAUX POSITIF que j'ai introduit la veille. En faisant entrer la
    session dans l'empreinte de TOUTES les portées, la portée PROJET se
    fragmentait par session : une règle de projet cessait de s'appliquer dès
    que `ANONPROXY_SESSION` changeait — c'est-à-dire à chaque session, ce qui
    est sa raison d'être. « Projet sert de défaut à session » ne voulait plus
    rien dire, et la portée projet devenait synonyme de la portée session."""
    racine = tmp_path / "policy"
    a = Policy(racine=racine, master_key=MASTER, scope_key="proj:acme",
               session="s-A")
    b = Policy(racine=racine, master_key=MASTER, scope_key="proj:acme",
               session="s-B")
    a.definir("projet", "type", "HOSTNAME", Decision.REVELER)
    assert b.decide("HOSTNAME", "infra", HOTE)[0] is Decision.REVELER

    # L'AUTRE MOITIÉ : une règle de SESSION, elle, ne traverse toujours pas.
    a.definir("session", "type", "IP_ADDRESS", Decision.REVELER)
    assert b.decide("IP_ADDRESS", "infra", "10.1.2.3")[0] is Decision.ANONYMISER


@pytest.mark.parametrize("valeur", [
    "srv-01\ud800.example",   # demi-paire haute, seule
    "a\ud800b\udc00c",        # deux demi-paires séparées
])
def test_une_demi_paire_de_substitution_est_substituee_pas_un_plantage(tmp_path, valeur):
    """HAUT. `json.loads` accepte `"\\ud800"` ; UTF-8 le refuse. L'encodage
    levait une `UnicodeEncodeError` qui traversait `decide` puis
    `substitute_value` : un 500 non structuré là où le contrat promet que la
    valeur est SUBSTITUÉE.

    Corriger l'empreinte seule ne faisait que déplacer le plantage dans le
    coffre, puis dans sa relecture — trois crans successifs. **Une valeur
    traverse la chaîne entière ou n'y entre nulle part.**"""
    politique = make_policy(tmp_path)
    coffre = Vault(tmp_path / "s.db", master_key=MASTER)
    moteur = SurrogateEngine(vault=coffre, master_key=MASTER, scope_key=SCOPE,
                             policy=politique)
    substitut = moteur.substitute_value("HOSTNAME", valeur)
    assert substitut != valeur
    assert coffre.view(SCOPE).get(substitut) == valeur, "relecture altérée"


def test_retirer_refuse_une_portee_inconnue_sans_planter(tmp_path):
    """`definir` validait sa portée, `retirer` non : `KeyError` nu là où toutes
    les autres écritures rendent un refus nommé."""
    with pytest.raises(PolitiqueInvalide, match="portée inconnue"):
        make_policy(tmp_path).retirer("portee_inconnue", "type", "HOSTNAME")


# --------------------------------------------------------------------------- #
# Répondre pour UN SEUL message
# --------------------------------------------------------------------------- #
def _politique_message(tmp_path):
    return Policy(racine=tmp_path / "pol", master_key="d4" * 32,
                  scope_key="project:message")


def test_une_reponse_de_message_l_emporte_sur_toute_regle(tmp_path):
    """C'est la portée la plus PROCHE : elle bat même la session.

    La hiérarchie du projet dit « le plus étroit et le plus proche l'emporte ».
    Une réponse donnée pour le message en cours est ce qu'il y a de plus proche
    qui soit."""
    p = _politique_message(tmp_path)
    p.definir("session", "type", "DATE", Decision.ANONYMISER)
    p.debut_message()
    p.repondre_pour_le_message("type", "DATE", Decision.REVELER)
    assert p.decide("DATE", "infra", "3 février 2026") == (
        Decision.REVELER, "message:type")


def test_une_reponse_de_message_NE_SURVIT_PAS_au_message(tmp_path):
    """Le cœur du dessin, et sa seule raison d'être.

    Une révélation qui survit à ce pour quoi elle a été accordée est une
    révélation HÉRITÉE, ce que la philosophie du projet interdit. Ici elle ne
    peut pas survivre : il n'y a pas de règle à révoquer, seulement une réponse
    qui meurt."""
    p = _politique_message(tmp_path)
    p.debut_message()
    p.repondre_pour_le_message("type", "DATE", Decision.REVELER)
    assert p.decide("DATE", "infra", "3 février 2026")[0] is Decision.REVELER
    p.debut_message()
    assert p.decide("DATE", "infra", "3 février 2026") == (
        Decision.ANONYMISER, None)


def test_une_reponse_arrivee_TROP_TARD_ne_s_applique_pas(tmp_path):
    """Le seul trou du dessin, et il est fermé par l'ouverture, pas par la
    fermeture.

    Une réponse écrite APRÈS la fin du message qu'elle visait s'appliquerait au
    SUIVANT — donc à des valeurs que l'opérateur n'a jamais vues. Vider à
    l'ouverture la jette. Une réponse perdue laisse la valeur anonymisée ;
    l'inverse la laisserait sortir."""
    p = _politique_message(tmp_path)
    p.debut_message()
    p.repondre_pour_le_message("classe", "infra", Decision.REVELER)
    p.debut_message()          # le message suivant commence
    assert p.decide("HOSTNAME", "infra", "db-01.acme.internal") == (
        Decision.ANONYMISER, None)


def test_un_SECRET_ne_se_revele_pas_meme_pour_un_message(tmp_path):
    """DEUX gardes, et il en faut deux.

    À l'ÉCRITURE, la réponse est REFUSÉE — un refus que l'opérateur lit vaut
    mieux qu'une réponse ignorée en silence plus tard, et c'est ce que fait
    déjà `definir`. À la LECTURE, `decide` court-circuite sur D4 quoi qu'il
    arrive : ce garde-là est l'INVARIANT, et il ne doit pas dépendre du
    premier — sinon un chemin d'écriture oublié ouvrirait un secret.
    """
    p = _politique_message(tmp_path)
    p.debut_message()
    with pytest.raises(PolitiqueInvalide):
        p.repondre_pour_le_message("classe", "secret", Decision.REVELER)
    # Et même si la réponse était écrite par un autre chemin, la lecture ferme.
    p._reponses.parent.mkdir(parents=True, exist_ok=True)
    p._reponses.write_text(
        '{"granularite":"classe","cle":"secret","decision":"reveler"}\n',
        encoding="utf-8")
    assert p.decide("AUTH_TOKEN", "secret", "ghp_x") == (
        Decision.ANONYMISER, "invariant:D4")


def test_une_reponse_de_message_couvre_le_GROUPE(tmp_path):
    """« Groupe de valeurs » est la demande : l'opérateur qui voit passer
    trente dates en tranche trente d'un coup, pour ce message."""
    p = _politique_message(tmp_path)
    p.debut_message()
    p.repondre_pour_le_message("type", "DATE", Decision.REVELER)
    for valeur in ("3 février 2026", "12 mars 2019", "August 2026"):
        assert p.decide("DATE", "infra", valeur)[0] is Decision.REVELER
    # Un autre type du même message n'est pas ouvert pour autant.
    assert p.decide("HOSTNAME", "infra", "db-01.acme.internal")[0] \
        is Decision.ANONYMISER


def test_une_granularite_inconnue_est_REFUSEE(tmp_path):
    """Fail-closed jusque dans l'écriture : une granularité que personne ne lit
    laisserait croire à une réponse donnée."""
    p = _politique_message(tmp_path)
    with pytest.raises(PolitiqueInvalide):
        p.repondre_pour_le_message("message", "DATE", Decision.REVELER)
