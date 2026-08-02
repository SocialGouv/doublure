"""Phase 6 — le coffre au repos.

La documentation affirme que « la clé + la base sont les deux moitiés du
secret ». Ce test l'exige : le fichier de base, à lui seul, ne doit rien
révéler des valeurs réelles, et sans la bonne clé la lecture échoue au lieu de
renvoyer n'importe quoi.

Données synthétiques uniquement.
"""
from __future__ import annotations

import sqlite3

import pytest

from anonproxy.vault import Vault, VaultUnavailableError

KEY_A = "aa" * 32
KEY_B = "bb" * 32
SCOPE = "project:rest"

REELS = [
    ("HOSTNAME", "db-master-01-prod.acmecorp.internal", "cluster-01.northwind.internal"),
    ("EMAIL_ADDRESS", "alice.dupont@acmecorp.example", "avery.lane@lucerne.example"),
    ("IP_ADDRESS", "10.1.2.3", "10.42.7.13"),
]


def remplir(path, key=KEY_A) -> Vault:
    v = Vault(path, master_key=key)
    for etype, reel, faux in REELS:
        v.bind(SCOPE, etype, reel, faux)
    return v


def test_le_fichier_seul_ne_revele_rien(tmp_path):
    """Un lecteur du fichier (sauvegarde égarée, disque volé) ne doit trouver
    aucune valeur réelle — c'est la promesse « deux moitiés du secret »."""
    p = tmp_path / "v.db"
    remplir(p).close()
    brut = p.read_bytes()
    for _etype, reel, _faux in REELS:
        assert reel.encode() not in brut, f"{reel!r} est en clair dans le coffre"
    # …et la lecture SQL directe ne donne rien d'exploitable non plus
    lignes = sqlite3.connect(p).execute("SELECT * FROM mapping").fetchall()
    assert lignes, "le coffre est vide, le test ne prouve rien"
    for ligne in lignes:
        texte = " ".join(str(c) for c in ligne)
        for _etype, reel, _faux in REELS:
            assert reel not in texte


def test_le_scelle_est_indistinguable_du_hasard(tmp_path):
    """« Rien en clair » ne suffit pas : un simple base64 satisferait ce
    critère tout en étant décodable par quiconque. On exige donc les
    propriétés d'un vrai chiffrement — entropie et incompressibilité."""
    import collections
    import zlib

    p = tmp_path / "v.db"
    v = remplir(p)
    # une valeur longue et TRÈS redondante : elle se compresserait à ~2 % si
    # elle n'était qu'encodée, et l'histogramme trahirait l'alphabet base64.
    v.bind(SCOPE, "HOSTNAME", "aaaaaaaa." * 40 + "acme.internal", "test.northwind.internal")
    v.close()

    blob = sqlite3.connect(p).execute(
        "SELECT real_enc FROM mapping WHERE surrogate='test.northwind.internal'"
    ).fetchone()[0]

    assert len(zlib.compress(bytes(blob), 9)) > 0.95 * len(blob), \
        "le scellé se compresse : ce n'est pas du chiffrement"
    distincts = len(collections.Counter(bytes(blob)))
    assert distincts > 100, f"seulement {distincts} valeurs d'octets : alphabet restreint"


def test_alteration_d_un_octet_detectee(tmp_path):
    """Chiffrement AUTHENTIFIÉ : avec la BONNE clé, un octet modifié doit
    faire échouer la lecture. Un simple encodage, ou un condensé non secret,
    laisserait passer l'altération."""
    p = tmp_path / "v.db"
    remplir(p).close()

    conn = sqlite3.connect(p)
    surrogate, blob = conn.execute("SELECT surrogate, real_enc FROM mapping LIMIT 1").fetchone()
    altere = bytearray(blob)
    altere[-1] ^= 0x01  # un seul bit, dans le chiffré
    conn.execute("UPDATE mapping SET real_enc=? WHERE surrogate=?", (bytes(altere), surrogate))
    conn.commit()
    conn.close()

    with pytest.raises(VaultUnavailableError):
        Vault(p, master_key=KEY_A).get_real(SCOPE, surrogate)


def test_scelle_deplace_d_une_ligne_a_l_autre_rejete(tmp_path):
    """Les données associées lient le scellé à SA ligne : sans elles, qui peut
    écrire dans le fichier échange deux `real_enc` et inverse silencieusement
    deux correspondances, sans invalider aucun tag."""
    p = tmp_path / "v.db"
    remplir(p).close()

    conn = sqlite3.connect(p)
    (s1, b1), (s2, b2) = conn.execute(
        "SELECT surrogate, real_enc FROM mapping LIMIT 2"
    ).fetchall()
    conn.execute("UPDATE mapping SET real_enc=? WHERE surrogate=?", (b2, s1))
    conn.execute("UPDATE mapping SET real_enc=? WHERE surrogate=?", (b1, s2))
    conn.commit()
    conn.close()

    v = Vault(p, master_key=KEY_A)
    with pytest.raises(VaultUnavailableError):
        v.get_real(SCOPE, s1)


def test_longueur_du_scelle_ne_trahit_pas_celle_du_reel(tmp_path):
    """Sans rembourrage, la taille du chiffré donne la longueur EXACTE de la
    valeur réelle : couplée au type et au décompte, elle permet d'énumérer des
    noms plausibles."""
    p = tmp_path / "v.db"
    v = Vault(p, master_key=KEY_A)
    tailles = {}
    for n in (5, 6, 7, 8, 20, 21, 22):
        v.bind(SCOPE, "HOSTNAME", "x" * n + ".internal", f"s{n}.northwind.internal")
    v.close()
    for surrogate, enc in sqlite3.connect(p).execute("SELECT surrogate, real_enc FROM mapping"):
        tailles.setdefault(len(enc), []).append(surrogate)
    assert any(len(v) > 1 for v in tailles.values()), \
        "chaque longueur réelle produit une taille de scellé distincte"


def test_mauvaise_cle_ne_dechiffre_pas(tmp_path):
    """Fail-closed : sans la bonne clé, on refuse, on ne devine pas."""
    p = tmp_path / "v.db"
    remplir(p).close()
    autre = Vault(p, master_key=KEY_B)
    for _etype, _reel, faux in REELS:
        with pytest.raises(VaultUnavailableError):
            autre.get_real(SCOPE, faux)


def test_bonne_cle_restitue_a_l_identique(tmp_path):
    p = tmp_path / "v.db"
    remplir(p).close()
    v = Vault(p, master_key=KEY_A)
    for etype, reel, faux in REELS:
        assert v.get_real(SCOPE, faux) == reel
        assert v.get_surrogate(SCOPE, etype, reel) == faux
    assert v.view(SCOPE) == {faux: reel for _e, reel, faux in REELS}


def test_injectivite_toujours_garantie(tmp_path):
    """Le chiffrement ne doit pas affaiblir la contrainte d'unicité (D6)."""
    from anonproxy.vault import SurrogateConflict

    v = remplir(tmp_path / "v.db")
    with pytest.raises(SurrogateConflict):
        v.bind(SCOPE, "HOSTNAME", "autre.acmecorp.internal", REELS[0][2])
    # et la même valeur réelle redonne bien le même substitut
    assert v.bind(SCOPE, REELS[0][0], REELS[0][1], "peu-importe") == REELS[0][2]


def test_recherche_deterministe_malgre_le_chiffrement(tmp_path):
    """Le chiffrement authentifié utilise un nonce aléatoire : la recherche
    doit passer par un index dérivé, sinon deux écritures de la même valeur
    deviennent introuvables."""
    v = remplir(tmp_path / "v.db")
    for etype, reel, faux in REELS:
        assert v.get_surrogate(SCOPE, etype, reel) == faux
    assert v.real_exists(SCOPE, REELS[0][1])
    assert not v.real_exists(SCOPE, "jamais-vu.acmecorp.internal")


def test_portees_cloisonnees(tmp_path):
    v = remplir(tmp_path / "v.db")
    assert v.get_surrogate("project:autre", REELS[0][0], REELS[0][1]) is None
    assert v.view("project:autre") == {}


def test_coffre_en_clair_refuse(tmp_path):
    """Un coffre d'une version antérieure (valeurs en clair) doit être REFUSÉ,
    pas lu silencieusement : ses données ne sont pas protégées."""
    p = tmp_path / "ancien.db"
    conn = sqlite3.connect(p)
    conn.executescript(
        "CREATE TABLE mapping (scope TEXT, etype TEXT, real TEXT, surrogate TEXT,"
        " created_at TEXT, PRIMARY KEY (scope, etype, real));"
    )
    conn.execute("INSERT INTO mapping VALUES ('s','HOSTNAME','a.acme.internal','x','')")
    conn.commit()
    conn.close()
    with pytest.raises(VaultUnavailableError) as exc:
        Vault(p, master_key=KEY_A)
    assert "clair" in str(exc.value).lower()
