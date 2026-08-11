"""The interception authority — written before the code that satisfies it.

A forward proxy that inspects TLS needs a certificate the client accepts. That
means a local authority, which is a **permanent lever on the machine**: anything
trusting it can impersonate any site. So the properties below are not polish,
they are the reason this is allowed to exist at all.

1. The key lives in the STATE directory, `0600`, never in the repository — the
   agent has no access to that directory, and a repository gets shared.
2. It is NEVER installed in the system trust store. Trust is carried by the
   ENVIRONMENT of the launched process (`NODE_EXTRA_CA_CERTS`,
   `SSL_CERT_FILE`…), so it dies with the session that used it. A system-wide
   authority would outlive the need and be worse than the leak it prevents.
3. It PERSISTS across restarts: regenerating would invalidate the trust already
   handed to a running agent, and a proxy that breaks every session it was
   meant to protect gets turned off.
"""
from __future__ import annotations

import stat
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store

from anonproxy.forward.ca import InterceptionCA


@pytest.fixture
def ca(tmp_path):
    return InterceptionCA(tmp_path / "state")


def _cert(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)


def _empreinte(pem: bytes) -> bytes:
    return _cert(pem).fingerprint(hashes.SHA256())


def test_the_private_key_is_not_readable_by_anyone_else(ca):
    ca.ensure()
    mode = stat.S_IMODE(ca.key_path.stat().st_mode)
    assert mode == 0o600, oct(mode)


def test_the_authority_persists_across_instances(ca, tmp_path):
    ca.ensure()
    avant = _empreinte(ca.cert_path.read_bytes())
    autre = InterceptionCA(tmp_path / "state")
    autre.ensure()
    assert _empreinte(autre.cert_path.read_bytes()) == avant, \
        "regenerating breaks the trust already handed to a running client"


def test_the_authority_says_what_it_is(ca):
    ca.ensure()
    cert = _cert(ca.cert_path.read_bytes())
    nom = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert "doublure" in nom.lower(), nom
    contraintes = cert.extensions.get_extension_for_oid(
        ExtensionOID.BASIC_CONSTRAINTS).value
    assert contraintes.ca is True
    # Elle ne signe QUE des feuilles : elle ne délègue à personne.
    assert contraintes.path_length == 0


def test_a_leaf_chains_to_the_authority_and_carries_the_host(ca):
    pem_cert, _ = ca.leaf_for("api.example.test")
    feuille = _cert(pem_cert)
    assert feuille.issuer == _cert(ca.cert_path.read_bytes()).subject
    noms = feuille.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
            x509.DNSName)
    assert noms == ["api.example.test"]
    contraintes = feuille.extensions.get_extension_for_oid(
        ExtensionOID.BASIC_CONSTRAINTS).value
    assert contraintes.ca is False, "une feuille qui peut signer est une seconde CA"


def test_a_literal_address_gets_an_address_alternative_name(ca):
    """Un client qui joint `https://127.0.0.1/` vérifie un SAN de type IP :
    un DNSName portant les mêmes chiffres ne le satisfait pas."""
    pem_cert, _ = ca.leaf_for("127.0.0.1")
    adresses = _cert(pem_cert).extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
            x509.IPAddress)
    assert [str(a) for a in adresses] == ["127.0.0.1"]


def test_the_same_host_reuses_its_leaf(ca):
    """Une session touche le même hôte des dizaines de fois ; regénérer à
    chaque poignée de main coûterait sa latence à chaque requête."""
    assert ca.leaf_for("api.example.test") == ca.leaf_for("api.example.test")
    assert ca.leaf_for("autre.example.test") != ca.leaf_for("api.example.test")


def test_a_leaf_is_valid_now_and_not_forever(ca):
    pem_cert, _ = ca.leaf_for("api.example.test")
    feuille = _cert(pem_cert)
    maintenant = datetime.now(timezone.utc)
    assert feuille.not_valid_before_utc <= maintenant <= feuille.not_valid_after_utc
    duree = feuille.not_valid_after_utc - feuille.not_valid_before_utc
    assert duree.days <= 90, "une feuille interceptrice n'a pas à vivre longtemps"


def test_a_client_trusting_the_authority_validates_the_chain(ca):
    """La vraie question. Les extensions peuvent être correctes une par une et
    la chaîne être refusée : c'est la validation complète — chaîne, dates,
    usages et NOM D'HÔTE — qui décide, comme chez le client."""
    pem_cert, pem_key = ca.leaf_for("api.example.test")
    magasin = Store([_cert(ca.cert_path.read_bytes())])
    verificateur = PolicyBuilder().store(magasin).build_server_verifier(
        x509.DNSName("api.example.test"))
    verificateur.verify(_cert(pem_cert), [])
    serialization.load_pem_private_key(pem_key, password=None)


def test_the_chain_is_refused_for_another_host(ca):
    """Le pendant : sans lui, le test précédent passerait avec un SAN faux."""
    pem_cert, _ = ca.leaf_for("api.example.test")
    magasin = Store([_cert(ca.cert_path.read_bytes())])
    verificateur = PolicyBuilder().store(magasin).build_server_verifier(
        x509.DNSName("autre.example.test"))
    with pytest.raises(Exception):
        verificateur.verify(_cert(pem_cert), [])


def test_the_authority_is_never_installed_system_wide(ca, tmp_path):
    """Test de CONCEPTION : rien ne doit être écrit hors du répertoire d'état.
    La confiance se transporte par l'environnement du processus lancé, et meurt
    avec lui."""
    ca.ensure()
    ca.leaf_for("api.example.test")
    ecrits = {p for p in (tmp_path / "state").rglob("*") if p.is_file()}
    assert ecrits == {ca.cert_path, ca.key_path}, ecrits
    for methode in dir(ca):
        assert "install" not in methode.lower(), methode
