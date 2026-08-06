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
    """L'arbitrage que je proposais devient un réglage : les deux marchent."""
    from anonproxy.surrogates.lexicon import EXTERNAL_TLDS, RESERVED_TLDS

    externe = "www-01.acmecorp-externe.fr"
    politique = make_policy(tmp_path)
    politique.definir_reglage("projet", "domaines_fictifs", DOMAINES_RESERVES)
    faux = make_engine(tmp_path, politique).substitute_value("HOSTNAME", externe)
    assert faux.rsplit(".", 1)[-1] in RESERVED_TLDS, faux

    politique2 = make_policy(tmp_path / "b")
    faux2 = make_engine(tmp_path / "b", politique2, nom="c").substitute_value(
        "HOSTNAME", externe)
    assert faux2.rsplit(".", 1)[-1] in EXTERNAL_TLDS, faux2
